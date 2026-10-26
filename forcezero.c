/*
 * forcezero — make a running process terminate with a chosen exit status.
 *
 * Usage:  forcezero <pid> [exit-code]      (exit-code defaults to 0, range 0..255)
 *         forcezero -h | --help
 *
 * How it works (x86-64 Linux, PTRACE_SEIZE based):
 *
 *   1. Seize the target and interrupt it (no SIGSTOP is ever delivered).
 *   2. Read the target's ELF header through /proc/<pid>/maps + ptrace and
 *      resolve the runtime address of its entry point (_start, which is dead
 *      code once the process has started).
 *   3. Overwrite the first 12 bytes there with an exit_group() payload that is
 *      embedded in this binary — nothing is ever written to disk:
 *
 *          mov edi, rc ; mov eax, 231 ; syscall        (64-bit target)
 *          mov ebx, rc ; mov eax, 252 ; int 0x80       (32-bit compat target)
 *
 *   4. Point RIP at the payload and detach.  Every thread of the target exits
 *      with the requested status, which propagates to whoever waits on it
 *      (shell, CI runner, build system, ...).
 *
 * The payload needs no libc, no symbols and no writable page inside the target,
 * so static, stripped and setuid binaries work alike (given the privileges to
 * trace them).  Targets that are job-control stopped stay stopped; they exit
 * with the status once continued.
 *
 * Permissions: tracing needs the same uid (with yama ptrace_scope 0) or
 * root / CAP_SYS_PTRACE.  Typical invocation: `sudo forcezero <pid>`.
 *
 * Build:  cc -O2 -Wall -Wextra -o forcezero forcezero.c
 */

#if !defined(__x86_64__)
#error "forcezero supports x86-64 hosts only (x86-64 and i386 targets)"
#endif

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAP_MAX     4096
#define PAYLOAD_LEN 12
#define PATCH_WORDS 3

struct mapping {
    uint64_t start, end, file_off;
    unsigned dev_major, dev_minor;
    unsigned long inode;
    int exec;
};

struct inject_state {
    int attached;
    int memory_patched;
    int regs_set;
    uint64_t win_addr;
    size_t win_words;
    long saved_words[PATCH_WORDS];
    struct user_regs_struct regs;   /* original registers */
    struct mapping maps[MAP_MAX];
    size_t nmaps;
};

static const char *prog = "forcezero";
static struct inject_state state;

/* ---- diagnostics ---------------------------------------------------------- */

static void perr(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void perr(const char *fmt, ...)
{
    int err = errno;
    va_list ap;

    fprintf(stderr, "%s: ", prog);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (err)
        fprintf(stderr, ": %s", strerror(err));
    fputc('\n', stderr);
}

/* ---- target memory access ------------------------------------------------- */

static int peek_word(pid_t pid, uint64_t addr, long *out)
{
    long v;

    errno = 0;
    v = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)addr, NULL);
    if (v == -1 && errno)
        return -1;
    *out = v;
    return 0;
}

static int poke_word(pid_t pid, uint64_t addr, long v)
{
    return ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)addr, (void *)(uintptr_t)v);
}

/*
 * Overwrite [addr, addr+len) in the target.  Writes happen in whole words, so
 * the surrounding bytes of the first and last word are read first and merged
 * back; `saved` receives the original window for a later restore_memory().
 */
static int patch_memory(pid_t pid, uint64_t addr, const unsigned char *bytes, size_t len,
                        uint64_t *win_addr, size_t *win_words, long *saved)
{
    uint64_t start = addr & ~(uint64_t)7;
    size_t off = (size_t)(addr - start);
    size_t words = (off + len + 7) / 8;
    unsigned char win[PATCH_WORDS * 8];
    size_t i;

    if (words > PATCH_WORDS) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < words; i++) {
        long w;

        if (peek_word(pid, start + i * 8, &w) != 0)
            return -1;
        saved[i] = w;
        memcpy(win + i * 8, &w, 8);
    }
    memcpy(win + off, bytes, len);
    for (i = 0; i < words; i++) {
        long w;

        memcpy(&w, win + i * 8, 8);
        if (poke_word(pid, start + i * 8, w) != 0)
            return -1;
    }
    *win_addr = start;
    *win_words = words;
    return 0;
}

static void restore_memory(pid_t pid, uint64_t win_addr, size_t win_words, const long *saved)
{
    size_t i;

    for (i = 0; i < win_words; i++)
        (void)poke_word(pid, win_addr + i * 8, saved[i]);
}

/* ---- /proc/<pid>/maps ----------------------------------------------------- */

static int read_maps(pid_t pid, struct mapping *maps, size_t max, size_t *n)
{
    char path[64], line[1024];
    FILE *fp;

    snprintf(path, sizeof(path), "/proc/%ld/maps", (long)pid);
    fp = fopen(path, "r");
    if (!fp)
        return -1;

    *n = 0;
    while (fgets(line, sizeof(line), fp) && *n < max) {
        struct mapping m;
        char perms[8];
        unsigned long long start, end, off;
        unsigned maj, min;
        unsigned long ino;

        if (sscanf(line, "%llx-%llx %7s %llx %x:%x %lu",
                   &start, &end, perms, &off, &maj, &min, &ino) != 7)
            continue;
        m.start = start;
        m.end = end;
        m.file_off = off;
        m.exec = (perms[2] == 'x');
        m.dev_major = maj;
        m.dev_minor = min;
        m.inode = ino;
        maps[(*n)++] = m;
    }
    fclose(fp);
    return 0;
}

static const struct mapping *map_containing(const struct mapping *maps, size_t n,
                                            uint64_t addr, int need_exec)
{
    size_t i;

    for (i = 0; i < n; i++)
        if (addr >= maps[i].start && addr < maps[i].end && (!need_exec || maps[i].exec))
            return &maps[i];
    return NULL;
}

static int exe_devino(pid_t pid, unsigned *maj, unsigned *min, unsigned long *ino)
{
    char path[64];
    struct stat st;

    snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid);
    if (stat(path, &st) != 0)
        return -1;
    *maj = major(st.st_dev);
    *min = minor(st.st_dev);
    *ino = st.st_ino;
    return 0;
}

/*
 * Find where to put the payload.  Preferred spot is the entry point of the
 * main executable: it is guaranteed to be executable, page-aligned enough to
 * hold 12 bytes, and dead code for any process that already started.  If the
 * ELF header is unavailable, fall back to the first roomy executable mapping.
 */
static int find_patch_addr(pid_t pid, const struct mapping *maps, size_t n,
                           int is64, uint64_t *out)
{
    unsigned maj = 0, min = 0;
    unsigned long ino = 0;
    uint64_t base = 0;
    int have_exe = 0, have_base = 0;
    size_t i;

    *out = 0;
    if (exe_devino(pid, &maj, &min, &ino) == 0) {
        have_exe = 1;
        for (i = 0; i < n; i++) {
            if (maps[i].inode == ino && maps[i].dev_major == maj &&
                maps[i].dev_minor == min && maps[i].file_off == 0) {
                base = maps[i].start;
                have_base = 1;
                break;
            }
        }
    }

    if (have_base) {
        long w0, wtype, wentry;

        if (peek_word(pid, base, &w0) == 0 && peek_word(pid, base + 16, &wtype) == 0 &&
            peek_word(pid, base + 24, &wentry) == 0 && (w0 & 0xffffffffU) == 0x464c457fU) {
            int etype = (int)((unsigned long)wtype & 0xffffU);
            uint64_t entry = is64 ? (uint64_t)wentry : (uint32_t)wentry;

            if (etype == ET_DYN)
                entry += base;
            if (etype == ET_DYN || etype == ET_EXEC) {
                const struct mapping *m = map_containing(maps, n, entry, 1);

                if (m && PAYLOAD_LEN <= m->end - entry) {
                    *out = entry;
                    return 0;
                }
            }
        }
    }

    /* Fallback: a roomy executable page of the main executable that is not
     * currently running any live function of interest. */
    for (i = 0; i < n; i++) {
        uint64_t a = maps[i].start + 0x100;

        if (!maps[i].exec)
            continue;
        if (have_exe && !(maps[i].inode == ino && maps[i].dev_major == maj &&
                          maps[i].dev_minor == min))
            continue;
        if (a + PAYLOAD_LEN <= maps[i].end) {
            *out = a;
            return 0;
        }
    }
    /* Last resort: any file-backed executable mapping. */
    for (i = 0; i < n; i++) {
        uint64_t a = maps[i].start + 0x100;

        if (maps[i].exec && maps[i].inode != 0 && a + PAYLOAD_LEN <= maps[i].end) {
            *out = a;
            return 0;
        }
    }
    return -1;
}

/* ---- payload -------------------------------------------------------------- */

/*
 * The injectable payload, embedded verbatim in this binary.  The first four
 * bytes of the "mov reg, imm32" instruction are patched with the requested
 * exit code at runtime; everything else is fixed.
 */
static const unsigned char payload_tmpl[2][PAYLOAD_LEN] = {
    /* mov edi, rc (bf imm32) ; mov eax, 231 (b8 e7 00 00 00) ; syscall (0f 05) */
    { 0xbf, 0x00, 0x00, 0x00, 0x00, 0xb8, 0xe7, 0x00, 0x00, 0x00, 0x0f, 0x05 },
    /* mov ebx, rc (bb imm32) ; mov eax, 252 (b8 fc 00 00 00) ; int 0x80 (cd 80) */
    { 0xbb, 0x00, 0x00, 0x00, 0x00, 0xb8, 0xfc, 0x00, 0x00, 0x00, 0xcd, 0x80 },
};

static void build_payload(unsigned char *buf, int is64, int code)
{
    uint32_t rc = (uint32_t)code;

    memcpy(buf, payload_tmpl[is64 ? 0 : 1], PAYLOAD_LEN);
    memcpy(buf + 1, &rc, 4);   /* immediate of "mov reg, imm32" */
}

/* ---- injection ------------------------------------------------------------ */

static void cleanup(pid_t pid)
{
    if (state.memory_patched)
        restore_memory(pid, state.win_addr, state.win_words, state.saved_words);
    if (state.regs_set)
        (void)ptrace(PTRACE_SETREGS, pid, NULL, &state.regs);
    if (state.attached)
        (void)ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

static int inject(pid_t pid, int code)
{
    struct user_regs_struct regs;
    unsigned char payload[PAYLOAD_LEN];
    uint64_t patch_addr;
    int status, is64;

    memset(&state, 0, sizeof(state));

    /* 1. Attach and stop the target. */
    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) == 0) {
        state.attached = 1;
        if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) != 0) {
            if (errno == ESRCH)
                goto gone;
            perr("interrupting pid %ld failed", (long)pid);
            goto fail;
        }
    } else if (errno == EINVAL) {
        /* Kernel without PTRACE_SEIZE (pre-3.4); plain attach will do. */
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0)
            goto attach_failed;
        state.attached = 1;
    } else {
        goto attach_failed;
    }

    if (waitpid(pid, &status, __WALL) < 0) {
        perr("waiting for pid %ld failed", (long)pid);
        goto fail;
    }
    if (!WIFSTOPPED(status))
        goto gone;

    /* 2. Grab the registers (we need the original set for rollback and the
     *    segment selector to tell 32-bit compat targets apart). */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &state.regs) != 0) {
        perr("reading registers of pid %ld failed", (long)pid);
        goto fail;
    }
    is64 = (state.regs.cs == 0x33);

    /* A thread parked inside execve() would replace its whole address space
     * the moment it is resumed, taking the payload with it.  Refuse politely. */
    if ((is64 && state.regs.orig_rax == 59) ||
        (!is64 && state.regs.orig_rax == 11)) {
        if (is64 ? (state.regs.rax == (unsigned long long)-ENOSYS)
                 : ((uint32_t)state.regs.rax == (uint32_t)-ENOSYS)) {
            errno = 0;
            perr("pid %ld is mid-exec, retry in a moment", (long)pid);
            goto fail;
        }
    }

    /* 3. Find the payload site. */
    if (read_maps(pid, state.maps, MAP_MAX, &state.nmaps) != 0) {
        perr("cannot read /proc/%ld/maps", (long)pid);
        goto fail;
    }
    if (find_patch_addr(pid, state.maps, state.nmaps, is64, &patch_addr) != 0) {
        errno = 0;
        perr("no usable executable page found in pid %ld", (long)pid);
        goto fail;
    }

    /* 4. Write the payload, hijack RIP, detach. */
    build_payload(payload, is64, code);
    if (patch_memory(pid, patch_addr, payload, PAYLOAD_LEN,
                     &state.win_addr, &state.win_words, state.saved_words) != 0) {
        perr("writing payload to pid %ld at 0x%llx failed",
             (long)pid, (unsigned long long)patch_addr);
        goto fail;
    }
    state.memory_patched = 1;

    regs = state.regs;
    regs.rip = patch_addr;
    /*
     * A thread stopped in an interruptible syscall may carry a pending
     * ERESTART_* in RAX; the kernel then rewrites the resume RIP (-2, to
     * re-execute the syscall instruction) *after* PTRACE_SETREGS, which
     * would land two bytes before our payload.  Clearing RAX makes the
     * kernel skip the restart dance and return to user space exactly at
     * the payload.
     */
    regs.rax = 0;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0) {
        perr("pointing pid %ld at the payload failed", (long)pid);
        goto fail;
    }
    state.regs_set = 1;

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) != 0) {
        perr("detaching from pid %ld failed", (long)pid);
        goto fail;
    }
    state.attached = 0;
    state.memory_patched = 0;   /* the payload stays; the target dies next */
    return 0;

attach_failed:
    {
        int err = errno;

        errno = 0;   /* errno text is part of the message already */
        if (err == ESRCH)
            perr("no process with pid %ld", (long)pid);
        else if (err == EPERM)
            perr("cannot ptrace pid %ld: %s; need the same uid (yama ptrace_scope 0) "
                 "or root/CAP_SYS_PTRACE — try 'sudo forcezero %ld'",
                 (long)pid, strerror(err), (long)pid);
        else
            perr("ptrace attach to pid %ld failed: %s", (long)pid, strerror(err));
    }
    return -1;

gone:
    fprintf(stderr, "%s: pid %ld already exited, nothing to inject\n", prog, (long)pid);
    return 0;

fail:
    cleanup(pid);
    return -1;
}

/* ---- cli ------------------------------------------------------------------ */

static void usage(FILE *fp)
{
    fputs(
"Usage: forcezero <pid> [exit-code]\n"
"\n"
"Force the running process <pid> to exit with <exit-code> (0..255, default 0).\n"
"The injectable payload is built into this executable; nothing is written to\n"
"disk, and the target keeps no trace of the injection in its files.\n"
"\n"
"Examples:\n"
"  sudo forcezero 12345        # process 12345 now exits with status 0\n"
"  sudo forcezero 12345 3      # ... with status 3\n"
"\n"
"Requires permission to ptrace <pid>: same uid (with yama ptrace_scope 0) or\n"
"root/CAP_SYS_PTRACE; 'sudo forcezero ...' covers the common cases.\n",
        fp);
}

int main(int argc, char **argv)
{
    pid_t pid;
    int code = 0;
    char *end;

    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(stdout);
        return 0;
    }
    if (argc < 2 || argc > 3) {
        usage(stderr);
        return 2;
    }

    errno = 0;
    pid = (pid_t)strtol(argv[1], &end, 10);
    if (errno || *end || end == argv[1] || pid <= 0) {
        perr("invalid pid '%s'", argv[1]);
        return 2;
    }
    if (argc == 3) {
        long c;

        errno = 0;
        c = strtol(argv[2], &end, 10);
        if (errno || *end || end == argv[2] || c < 0 || c > 255) {
            perr("exit code must be an integer in 0..255");
            return 2;
        }
        code = (int)c;
    }

    return inject(pid, code) == 0 ? 0 : 1;
}