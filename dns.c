#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <string.h>
#include <unistd.h>

#include "dns.h"

enum opcode {
	opcode_QUERY = 0,
};

#define A(a, b, c, d) .len = 4, .type = type_A, .value = (void*)(a|(b<<8)|(c<<16)|(d<<24))

#define chk_err(X, MSG) do { if (X) { perror(MSG); exit(1); } } while (0)
#define chk_warn(X, MSG) do { if (X) { perror(MSG); } } while (0)
#define arrsze(X) (sizeof(X) / sizeof(*(X)))
#define xstr(s) str(s)
#define str(s) #s
#define LOG(...) printf(__FILE__ ":" xstr(__LINE__) " " __VA_ARGS__)

#define IOV(Buf, Sze) (struct iovec){ .iov_base = Buf, .iov_len = Sze }
#define BACK(Msg) ((Msg)->msg_iov[(Msg)->msg_iovlen++])

struct dns_req {
	uint16_t id;
	uint16_t qr:1;
	uint16_t op:4;
	uint16_t aa:1;
	uint16_t tc:1;
	uint16_t rd:1;
	uint16_t ra:1;
	uint16_t z:3;
	uint16_t rcode:4;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
	char payload[0];
} __packed;

struct dns_ans {
	uint16_t name;
	uint16_t type;
	uint16_t class;
	struct record val[0];
} __packed;

static int fd_tcp, fd_udp;

static void init_sockets() {
	int optval = 1;
	struct sockaddr_in saddr = {
		.sin_family = AF_INET,
		.sin_port = htons(53),
	};
	struct sockaddr* sa = (struct sockaddr*)&saddr;

#define init_sock(T, Sock) do { \
	chk_err((fd_##T = socket(AF_INET, Sock, 0)) < 0, "socket(" #Sock ")"); \
	chk_err(setsockopt(fd_##T, SOL_SOCKET, SO_REUSEPORT, &optval, \
			   sizeof(optval)) < 0, "setsockopt"); \
	chk_err(setsockopt(fd_##T, SOL_SOCKET, SO_REUSEADDR, &optval, \
			   sizeof(optval)) < 0, "setsockopt"); \
	chk_err(bind(fd_##T, sa, sizeof(saddr)) < 0, "bind(" #T ")"); \
	} while (0)

	init_sock(udp, SOCK_DGRAM);
	init_sock(tcp, SOCK_STREAM);

#undef init_sock

	chk_err(listen(fd_tcp, 0) < 0, "listen(tcp)");
}

static int epoll_add(int epollfd, int fd, int events) {
	struct epoll_event ev = { };
	ev.events = events;
	ev.data.fd = fd;
	return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
}

typedef int (*send_fn)(struct msghdr* msg, void* data);

int find_record(enum type type, void* buf, size_t sze, struct iovec* iov) {
	static char space[24];
	struct record* r = (void*)space;

	r->ttl = 0;
	r->len = htons(4);
	*(int*)r->payload = 0xaa55aa55;

	*iov = IOV(r, sizeof(*r) + 4);

	return 0;
}

static int handle_QUERY(struct dns_req* rq, size_t sze, struct msghdr* msg,
			send_fn cb, void* data) {
	char* q = rq->payload;
	while (*q) {
		q += (unsigned int)*q + 1;
	}
	q++;
	uint16_t type = ntohs(*(uint16_t*)q);
	uint16_t class = ntohs(((uint16_t*)q)[1]);

	struct dns_ans ans;

	rq->qr = 1;
	rq->aa = 1;
	rq->qdcount = ntohs(1);
	rq->ancount = ntohs(1);

	ans.name = htons(0xc000 + sze - (sizeof(struct dns_req) +
					  2 * sizeof(uint16_t)));
	ans.type = htons(type);
	ans.class = htons(class);
	BACK(msg) = IOV(&ans, sizeof(ans));
	find_record(type, rq->payload, q - rq->payload, &BACK(msg));

	return cb(msg, data);
}

static int print_rq(struct dns_req* rq) {
	static const char* opcode_str[] = {
#define X(I) [opcode_##I] = #I
		X(QUERY),
#undef X
	};

	static const char* type_str[] = {
#define X(I) [type_##I] = #I
		X(A),
		X(NS),
		X(CNAME),
		X(SOA),
		X(PTR),
		X(MX),
		X(TXT),
		X(AAAA),
#undef X
	};

	printf("%s\n", opcode_str[rq->op]);

	size_t j = 0;
	size_t cnt = ntohs(rq->qdcount);
	for (size_t i = 0; i < cnt; i++) {
		printf("  - ");
		while (rq->payload[j]) {
			int sze = (uint8_t)rq->payload[j];
			printf("%.*s.", sze, rq->payload + j + 1);
			j += sze + 1;
		}
		j++;
		size_t type = ntohs(*(uint16_t*)&rq->payload[j]);
		printf(" (%s)\n", type_str[type]);
	}

	return 0;
}

static int handle_msg(struct dns_req* rq, size_t sze, struct msghdr* hdr,
		      send_fn cb, void* data) {
	int (*opcode_handler[])(struct dns_req*, size_t, struct msghdr*,
				send_fn, void*) = {
#define X(I) [opcode_##I] = handle_##I
		X(QUERY),
#undef X
	};

	if (rq->op >= arrsze(opcode_handler) || !opcode_handler[rq->op])
		return -1;
	print_rq(rq);
	return opcode_handler[rq->op](rq, sze, hdr, cb, data);
}

struct data_udp {
	struct sockaddr saddr;
	socklen_t saddrlen;
	int fd;
};

static int reply_udp(struct msghdr* msg, void* data) {
	struct data_udp* d = data;
	msg->msg_name = &d->saddr;
	msg->msg_namelen = d->saddrlen;

	return sendmsg(d->fd, msg, 0);
}

static int reply_tcp(struct msghdr* msg, void* data) {
	int fd = *(int*)data;

	size_t len = 0;
	for (size_t i = 0; i < msg->msg_iovlen; i++)
		len += msg->msg_iov[i].iov_len;

	len -= 2;
	*(uint16_t*)msg->msg_iov->iov_base = htons(len);

	int out = sendmsg(fd, msg, 0);
	close(fd);
	return out;
}

static void dns_loop(int efd) {
	struct iovec iov[8];
	struct msghdr msg = {
		.msg_iov = iov, // We may prepend the size with tcp
		.msg_iovlen = 0,
	};

	struct epoll_event ev[16];
	char buf[1024];
	char* ptr = buf;
	ssize_t sze;
	int nfds = epoll_wait(efd, ev, arrsze(ev), -1);
	chk_err(nfds < 0, "epoll_wait");

	for (int i = 0; i < nfds; i++) {
		union {
			struct data_udp udp;
			int fd;
		} data;
		send_fn fn;

		if (ev[i].data.fd == fd_tcp) {
			int fd = accept(fd_tcp, NULL, 0);
			chk_err(fd < 0, "accept");
			chk_err(epoll_add(efd, fd, EPOLLIN|EPOLLET) < 0,
					  "epoll_add");
			continue;
		} else if (ev[i].data.fd == fd_udp) {
			data.udp.saddrlen = sizeof(data.udp.saddr);
			data.udp.fd = fd_udp;
			sze = recvfrom(fd_udp, buf, sizeof(buf), MSG_DONTWAIT,
				       &data.udp.saddr, &data.udp.saddrlen);
			chk_warn(sze < 0, "recvfrom");
			fn = reply_udp;
			BACK(&msg) = IOV(ptr, sze);
		} else {
			sze = recv(ev[i].data.fd, buf, sizeof(buf), 0);
			chk_warn(sze < 0, "recv");
			sze = ntohs(*(uint16_t*)buf);
			ptr += 2;
			data.fd = ev[i].data.fd;
			fn = reply_tcp;
			BACK(&msg) = IOV(buf, sze + 2);
		}

		chk_warn(handle_msg((void*)ptr, sze, &msg, fn, &data) < 0,
			 "handle_msg");
	}
}

int main() {
	init_sockets();

	int efd = epoll_create1(0);
	chk_err(efd < 0, "epoll_create1");

	chk_err(epoll_add(efd, fd_tcp, EPOLLIN) < 0, "epoll_add");
	chk_err(epoll_add(efd, fd_udp, EPOLLIN) < 0, "epoll_add");

	while (1)
		dns_loop(efd);
}
