# Makefile for kbpsum, the CRCK checksum (Keith B. Petersen, CP/M 1979)
# as implemented by CRCK 6.71 for MS-DOS
#
#   make            build kbpsum
#   make check      build and run the checksum known-answer tests
#   make install    install to $(DESTDIR)$(PREFIX)/bin
#   make clean      remove build products

CC       ?= cc
CFLAGS   ?= -O2 -g
CFLAGS   += -std=c99 -Wall -Wextra -pedantic
CPPFLAGS += -D_XOPEN_SOURCE=700
LDFLAGS  ?=
PREFIX   ?= /usr/local
BINDIR    = $(PREFIX)/bin
INSTALL  ?= install

PROG      = kbpsum
OBJS      = kbpsum.o kbp_sum.o
TEST      = test_kbpsum
TEST_OBJS = test_kbpsum.o kbp_sum.o

.PHONY: all check install uninstall clean

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

$(TEST): $(TEST_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(TEST_OBJS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

kbpsum.o kbp_sum.o test_kbpsum.o: kbp_sum.h

check: $(TEST)
	./$(TEST)

install: $(PROG)
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 $(PROG) $(DESTDIR)$(BINDIR)/$(PROG)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(PROG)

clean:
	rm -f $(PROG) $(TEST) *.o
