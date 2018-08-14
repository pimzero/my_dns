LDLIBS=-lseccomp
CPPFLAGS=
CPPFLAGS+=-DUSE_TCP
CPPFLAGS+=-DUSE_SECCOMP
#CPPFLAGS+=-DUSE_BPF
BACKEND_OBJ?=backend_config.o
CPPFLAGS=-DLOG_LEVEL=LOG_WARN
CFLAGS=-Wall -Wextra
OBJS=dns.o $(BACKEND_OBJ)
BIN=dns

$(BIN): $(OBJS)

%.inc: %.bpf
	bpf_asm -c $< > $@

%.bpf: %.BPF
	$(CC) -E -xc -P $< > $@
