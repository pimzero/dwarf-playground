CPPFLAGS=-D_XOPEN_SOURCE
CFLAGS=-Wall -Wextra -std=c99 -O2 -ggdb

all: debug_line

debug_line: CFLAGS+=-Wno-unused-parameter
debug_line:
