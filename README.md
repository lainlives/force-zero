# forcezero

Make a **running** process terminate with a chosen exit status (default `0`) —
the runtime counterpart of the `exit0.so` preload helper in this repo:

    sudo ./forcezero <pid> [exit-code]

The injectable payload is embedded in the `forcezero` binary itself; nothing is
written to disk when injecting, and the target needs no libc, no symbols and no
writable code page.  Static, stripped, 32-bit (on x86-64 hosts) and
multithreaded processes all work.

## How it works

1. `PTRACE_SEIZE` + `PTRACE_INTERRUPT` stop the target without delivering any
   signal.
2. The target's entry point (`_start`, dead code once the process is running)
   is located via `/proc/<pid>/maps` and the ELF header read with
   `PTRACE_PEEKDATA`.
3. The first 12 bytes there are replaced with

       mov edi, rc      ; mov eax, 231 ; syscall       (64-bit targets)
       mov ebx, rc      ; mov eax, 252 ; int 0x80      (32-bit targets)

4. `RIP` is pointed at the payload and the tracer detaches.  The kernel's
   pending-syscall bookkeeping is neutralised (`rax = 0`) so the target resumes
   exactly at the payload and every thread exits with the requested status,
   which propagates to whoever waits on the target (shell, CI runner, ...).

If injection fails after the memory was already patched, the original bytes and
registers are restored and the target is left running.

## Build and test

    make            # build forcezero (and exit0.so)
    make check      # end-to-end tests; needs ptrace permission
    make install    # install forcezero into /usr/local/bin

The test suite covers dynamic and static binaries, non-PIE and PIE layouts,
multithreaded targets, a SIGSTOP-suspended target, and CLI error paths.

## Permissions

Tracing a process requires the same uid (with a kernel that permits it — on
systems with Yama, `kernel.yama.ptrace_scope=0` for same-uid tracing) or root /
`CAP_SYS_PTRACE`.  In practice:

    sudo forcezero 12345        # process 12345 now exits with status 0
    sudo forcezero 12345 3      # ... with status 3

## Notes and limitations

- x86-64 hosts; 32-bit compat targets are supported, so is anything with a
  normal ELF main executable.  Shell scripts work too (the interpreter gets
  the injection).
- The status range is 0..255 (a kernel exit-status limit).
- A target suspended with `SIGSTOP` stays suspended and exits with the
  requested status once continued.
- A process parked inside `execve()` would discard the injection; forcezero
  detects this and asks you to retry instead of silently doing nothing.