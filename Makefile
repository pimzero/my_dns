LDLIBS=-lseccomp
CPPFLAGS=-DUSE_SECCOMP
CFLAGS=-Wall -Wextra
OBJS=dns.o back.o
BIN=dns

$(BIN): $(OBJS)
