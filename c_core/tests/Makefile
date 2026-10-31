CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -I../include
LDFLAGS ?= -L.. -lcmonitor -lpcap

TESTS = test_parser

all: $(TESTS)
	./test_parser

test_parser: test_parser.c ../libcmonitor.a
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(TESTS) *.o

.PHONY: all clean
