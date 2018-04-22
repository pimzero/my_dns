#include "dns.h"

#define IP(A, B, C, D) ((A) | ((B) << 8) | ((C) << 16) | ((D) << 24))

int find_record(enum type type, void* buf, size_t sze, struct iovec* iov) {
	static char space[24];
	struct record* r = (void*)space;

	r->ttl = 0;
	r->len = htons(4);
	*(int*)r->payload = IP(139,99,103,127);

	*iov = IOV(r, sizeof(*r) + 4);

	return 0;
}
