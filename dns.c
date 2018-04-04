#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <string.h>
#include <unistd.h>

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
#define __packed __attribute__((packed))

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

struct record {
	uint32_t ttl;
	uint16_t len;
	char* payload[0];
} __packed;

struct recordb {
	uint32_t ttl;
	uint16_t len;
	char payload[];
} __packed;

struct recordb wat = {
	.ttl = 3600,
	.len = 16,
	.payload = { 127, 0, 0, 1 },
};

struct dns_ans {
	//uint16_t pad_1:2;
	//uint16_t name:14;
	uint16_t name;
	uint16_t type;
	uint16_t class;
	struct record val;
} __packed;

struct {
	const char* name;
	enum type type;
	union {
		struct record record;
		struct {
			uint32_t ttl;
			uint16_t len;
		} __packed;
	};
	void* value;
} entries[] = {
#define X(Name, Ttl, Type) { .name = Name, .ttl = Ttl, Type}
	X("www.google.fr", 60, A(127,0,0,1)),
#undef X
};


static int fd_tcp, fd_udp;

#if 0
static const char* opcode_to_str(uint16_t opcode) {
	const char* str[] = {
#define X(Op) [opcode_##Op] = #Op
		X(QUERY),
#undef X
	};
	if (opcode <= arrsze(str))
		return NULL;
	return str[opcode];
}

static const char* type_to_str(uint16_t type) {
	const char* str[] = {
#define X(Type) [type_##Type] = #Type
		X(A),
		X(NS),
		X(CNAME),
		X(SOA),
		X(PTR),
		X(MX),
		X(TXT),
		X(A),
#undef X
	};
	if (type >= arrsze(str))
		return NULL;
	return str[type];
}

static int set_nonblock(int fd) {
	return fcntl(fd, F_SETFL, fcntl(fd,F_GETFL) | O_NONBLOCK);
}
#endif

static void init_sockets() {
	int optval = 1;
	struct sockaddr_in saddr = {
		.sin_family = AF_INET,
		.sin_port = htons(53),
		.sin_addr = { 0 },
		.sin_zero = { 0 },
	};
	struct sockaddr* sa = (struct sockaddr*)&saddr;
	fd_udp = socket(AF_INET, SOCK_DGRAM, 0);
	chk_err(fd_udp < 0, "socket(SOCK_DGRAM)");
	chk_err(setsockopt(fd_udp, SOL_SOCKET, SO_REUSEPORT, &optval,
			   sizeof(optval)) < 0, "setsockopt");
	chk_err(bind(fd_udp, sa, sizeof(saddr)) < 0, "bind(udp)");

	fd_tcp = socket(AF_INET, SOCK_STREAM, 0);
	chk_err(fd_tcp < 0, "socket(SOCK_STREAM)");
	chk_err(setsockopt(fd_tcp, SOL_SOCKET, SO_REUSEPORT, &optval,
			   sizeof(optval)) < 0, "setsockopt");
	chk_err(bind(fd_tcp, sa, sizeof(saddr)) < 0, "bind(tcp)");
	chk_err(listen(fd_tcp, 0) < 0, "listen(tcp)");
}

static int epoll_add(int epollfd, int fd, int events) {
	struct epoll_event ev = { 0 };
	ev.events = events;
	ev.data.fd = fd;
	return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
}

typedef int (*send_fn)(void* msg, size_t len, void* data);

static int handle_msg(void* buf, size_t sze, send_fn reply, void* data) {
	struct dns_req* rq = buf;
#if 0
	printf("qdcount: %u\n", rq->qdcount);
	printf("id:%x qr:%d op:%d aa:%d tc:%d rd:%d ra:%d\n",
		ntohs(rq->id), rq->qr, rq->op, rq->aa, rq->tc, rq->rd, rq->ra);
#endif
	char* q = rq->payload;
	while (*q) {
		//printf("%u %.*s\n", (unsigned int)*q, (unsigned int)*q, q + 1);
		q += (unsigned int)*q + 1;
	}
	q++;
	uint16_t type = ntohs(*(uint16_t*)q);
	uint16_t class = ntohs(((uint16_t*)q)[1]);
#if 0
	printf("type: %d\n", type);
	printf("type: %s\n", type_to_str(type));
	printf("class: %d\n", class);
#endif

	//struct dns_ans* ans = (void*)&(((uint16_t*)q)[2]);
	struct dns_ans* ans = (void*)(((char*)buf) + sze);

	rq->qr = 1;
	rq->aa = 1;
	rq->qdcount = ntohs(1);
	rq->ancount = ntohs(1);

	//ans->pad_1 = 3;
	ans->name = htons(0xc000 + sze - (sizeof(struct dns_req) +
					  2 * sizeof(uint16_t)));
	ans->type = htons(type);
	ans->class = htons(class);
	ans->val.ttl = 0;
	ans->val.len = htons(4);
	*(int*)ans->val.payload = 0xaa55aa55;

	return reply(buf, sze + sizeof(struct dns_ans) + ntohs(ans->val.len), data);
}

struct data_udp {
	struct sockaddr saddr;
	socklen_t saddrlen;
	int fd;
};

static int reply_udp(void* msg, size_t sze, void* data) {
	struct data_udp* d = data;
	return sendto(d->fd, msg, sze, 0, &d->saddr, d->saddrlen);
}

static int reply_tcp(void* msg, size_t sze, void* data) {
	int fd = *(int*)data;

	memmove(msg + 2, msg, sze);
	*(uint16_t*)msg = htons(sze);

	int out = send(fd, msg, sze + 2, MSG_DONTWAIT);
	close(fd);
	return out;
}

static void dns_loop(int efd) {
	struct epoll_event ev[16];
	char buf_[1024];
	char* buf = buf_;
	ssize_t sze;
	int nfds = epoll_wait(efd, ev, arrsze(ev), -1);
	chk_err(nfds < 0, "epoll_wait");

	for (int i = 0; i < nfds; i++) {
		union {
			struct data_udp udp;
			int fd;
		} data = { 0 };
		send_fn fn;

		//printf(">> fd: %d (tcp:%d udp:%d)\n", ev[i].data.fd, fd_tcp, fd_udp);
		if (ev[i].data.fd == fd_tcp) {
			int fd = accept(fd_tcp, NULL, 0 /* 1? */);
			chk_err(fd < 0, "accept");
			chk_err(epoll_add(efd, fd, EPOLLIN|EPOLLET) < 0,
					  "epoll_add");
			continue;
		} else if (ev[i].data.fd == fd_udp) {
			data.udp.saddrlen = sizeof(data.udp.saddr);
			data.udp.fd = fd_udp;
			sze = recvfrom(fd_udp, buf, sizeof(buf_), MSG_DONTWAIT,
				       &data.udp.saddr, &data.udp.saddrlen);
			chk_warn(sze < 0, "recvfrom");
			fn = reply_udp;
		} else {
			sze = read(ev[i].data.fd, buf, sizeof(buf_));
			chk_warn(sze < 0, "recv");
			sze = ntohs(*(uint16_t*)buf);
			buf += 2;
			data.fd = ev[i].data.fd;
			fn = reply_tcp;
		}

		chk_err(handle_msg(buf, sze, fn, &data) < 0, "handle_msg");
		// remove
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
