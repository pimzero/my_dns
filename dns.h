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

enum rcode {
	rcode_ok = 0,
	rcode_servfail = 2,
	rcode_nxdomain = 3,
};

struct record {
	uint32_t ttl;
	uint16_t len;
	char payload[0];
} __packed;

struct dns_req {
	uint16_t id;
	uint16_t rd:1;
	uint16_t tc:1;
	uint16_t aa:1;
	uint16_t op:4;
	uint16_t qr:1;
	uint16_t rcode:4;
	uint16_t z:3;
	uint16_t ra:1;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
	char payload[0];
} __packed;

int find_record(enum type type, void* buf, size_t sze, struct iovec* value);
int backend_init(int argc, char** argv);
int backend_reload(void);

#ifdef USE_SECCOMP
int backend_seccomp_rule(scmp_filter_ctx* ctx);
#endif

#endif
