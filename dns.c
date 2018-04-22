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

#ifdef USE_SECCOMP
#include <seccomp.h>
#endif

enum opcode {
	opcode_QUERY = 0,
};

#define chk_err(X, MSG) do { if ((X)) { perror(MSG); exit(1); } } while (0)
#define chk_warn(X, MSG) do { if ((X)) { perror(MSG); } } while (0)
#define arrsze(X) (sizeof(X) / sizeof(*(X)))

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

static int handle_QUERY(struct dns_req* rq, size_t sze, send_fn cb,
			void* data) {
	struct iovec iov[8];
	struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = 0,
	};

	BACK(&msg) = IOV(rq, sze);

	char* q = rq->payload;
	while (*q) {
		q += (unsigned int)*q + 1;
	}
	q++;
	uint16_t type = ntohs(*(uint16_t*)q);
	uint16_t class = ntohs(((uint16_t*)q)[1]);

	sze = (4 + (char*)q) - ((char*)rq);
	msg.msg_iov[0].iov_len = sze;

	struct dns_ans ans;

	rq->qr = 1;
	rq->aa = 1;
	rq->qdcount = ntohs(1);
	rq->ancount = ntohs(1);
	rq->arcount = ntohs(0);

	ans.name = htons(0xc000 | sizeof(struct dns_req));
	ans.type = htons(type);
	ans.class = htons(class);
	BACK(&msg) = IOV(&ans, sizeof(ans));
	find_record(type, rq->payload, q - rq->payload, &BACK(&msg));

	return cb(&msg, data);
}

static int handle_msg(struct dns_req* rq, size_t sze, send_fn cb, void* data) {
	int (*opcode_handler[])(struct dns_req*, size_t, send_fn, void*) = {
#define X(I) [opcode_##I] = handle_##I
		X(QUERY),
#undef X
	};

	if (rq->op >= arrsze(opcode_handler) || !opcode_handler[rq->op])
		return -1;
	return opcode_handler[rq->op](rq, sze, cb, data);
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

	msg->msg_iov[0].iov_base -= 2;
	msg->msg_iov[0].iov_len += 2;

	*(uint16_t*)msg->msg_iov->iov_base = htons(len);

	int out = sendmsg(fd, msg, 0);
	close(fd);
	return out;
}

static void dns_iter(int fd) {
	char buf[1024];
	char* ptr = buf;
	ssize_t sze;

	union {
		struct data_udp udp;
		int fd;
	} data;
	send_fn fn;

	if (fd == fd_udp) {
		data.udp.saddrlen = sizeof(data.udp.saddr);
		data.udp.fd = fd_udp;
		sze = recvfrom(fd_udp, buf, sizeof(buf), MSG_DONTWAIT,
			       &data.udp.saddr, &data.udp.saddrlen);
		chk_warn(sze < 0, "recvfrom");
		fn = reply_udp;
	} else {
		sze = recv(fd, buf, sizeof(buf), 0);
		chk_warn(sze < 0, "recv");
		sze = ntohs(*(uint16_t*)buf);
		ptr += 2;
		data.fd = fd;
		fn = reply_tcp;
	}

	chk_warn(handle_msg((void*)ptr, sze, fn, &data) < 0, "handle_msg");
}

static void dns_new_tcp(int efd) {
	int afd = accept(fd_tcp, NULL, 0);
	chk_warn(afd < 0, "accept");
	chk_warn(epoll_add(efd, afd, EPOLLIN|EPOLLET) < 0, "epoll_add");
}

static void dns_loop(int efd) {
	struct epoll_event ev[16];
	int nfds = epoll_wait(efd, ev, arrsze(ev), -1);
	chk_err(nfds < 0, "epoll_wait");

	for (int i = 0; i < nfds; i++) {
		if (ev[i].data.fd == fd_tcp)
			dns_new_tcp(efd);
		else
			dns_iter(ev[i].data.fd);
	}
}

int main() {
	init_sockets();

	int efd = epoll_create1(0);
	chk_err(efd < 0, "epoll_create1");

	chk_err(epoll_add(efd, fd_tcp, EPOLLIN) < 0, "epoll_add");
	chk_err(epoll_add(efd, fd_udp, EPOLLIN) < 0, "epoll_add");

#ifdef USE_SECCOMP
	scmp_filter_ctx ctx;
	chk_err(!(ctx = seccomp_init(SCMP_ACT_KILL)), "seccomp_init");

#define X(S) chk_err(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(S), 0) < 0,\
		     "seccomp_rule_add(" #S ")");
	X(accept); X(close); X(epoll_ctl); X(epoll_pwait); X(epoll_wait);
	X(recv); X(recvfrom); X(sendmsg); X(write);
#undef X

	chk_err(seccomp_load(ctx) < 0, "seccomp_load");
#endif

	while (1)
		dns_loop(efd);
}
