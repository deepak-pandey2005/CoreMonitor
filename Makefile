CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -fPIC -I./c_core/include
LDFLAGS ?= -lpcap

C_LIB = c_core/libcmonitor.a
C_SRCS = $(wildcard c_core/src/*.c)
C_OBJS = $(C_SRCS:.c=.o)

all: $(C_LIB) build-go

$(C_LIB): $(C_OBJS)
	ar rcs $@ $^

c_core/src/%.o: c_core/src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

build-go: $(C_LIB)
	go build -o bin/coremonitor ./cmd/coremonitor

test-c: $(C_LIB)
	$(MAKE) -C c_core/tests

test-go:
	go test -v ./...

test: test-c test-go

clean:
	rm -f c_core/src/*.o $(C_LIB) bin/coremonitor
	$(MAKE) -C c_core/tests clean || true

.PHONY: all build-go test-c test-go test clean
