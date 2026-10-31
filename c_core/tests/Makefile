CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -I../include
LDFLAGS ?= -L.. -lcmonitor -lpcap

TESTS = test_parser test_ids

all: $(TESTS)
	./test_parser
	./test_ids

test_parser: test_parser.c ../libcmonitor.a
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test_ids: test_ids.c ../libcmonitor.a
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(TESTS) *.o

.PHONY: all clean
