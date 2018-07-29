LDLIBS=-lseccomp
CPPFLAGS=
CPPFLAGS+=-DUSE_TCP
CPPFLAGS+=-DUSE_SECCOMP
#CPPFLAGS+=-DUSE_BPF
CFLAGS=-Wall -Wextra
OBJS=dns.o back.o
BIN=dns

$(BIN): $(OBJS)

%.inc: %.bpf
	bpf_asm -c $< > $@

%.bpf: %.BPF
	$(CC) -E -xc -P $< > $@
