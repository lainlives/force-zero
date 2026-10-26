# forcezero — runtime exit-code injector
#
#   make            build forcezero and exit0.so
#   make check      run the end-to-end tests (needs ptrace permission)
#   make install    install forcezero into $(PREFIX)/bin

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
PREFIX  ?= /usr/local

all: forcezero exit0.so

forcezero: forcezero.c
	$(CC) $(CFLAGS) -o $@ $<

exit0.so: exit0.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

check: forcezero
	sh test.sh

install: forcezero
	install -D -m 0755 forcezero $(DESTDIR)$(PREFIX)/bin/forcezero

clean:
	rm -f forcezero exit0.so

.PHONY: all check clean install