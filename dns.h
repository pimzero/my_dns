#ifndef DNS_H
#define DNS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

#ifdef USE_SECCOMP
#include <seccomp.h>
#endif

#define __packed __attribute__((packed))
#define IOV(Buf, Sze) (struct iovec){ .iov_base = Buf, .iov_len = Sze }

enum type {
	type_A = 1,
	type_NS = 2,
	type_CNAME = 5,
	type_SOA = 6,
	type_PTR = 12,
	type_MX = 15,
	type_TXT = 16,
	type_AAAA = 28,
};

struct record {
	uint32_t ttl;
	uint16_t len;
	char payload[0];
} __packed;

int find_record(enum type type, void* buf, size_t sze, struct iovec* value);
int backend_init(int argc, char** argv);
int backend_reload(void);

#ifdef USE_SECCOMP
int backend_seccomp_rule(scmp_filter_ctx* ctx);
#endif

#endif
