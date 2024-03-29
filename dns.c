#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef USE_BPF
#ifdef USE_TCP
#error No support of TCP + BPF
#endif
#include <linux/filter.h>
#endif

#include "dns.h"

#define chk_err(X, MSG) do { if ((X)) { perror(MSG); exit(1); } } while (0)
#define chk_warn(X, MSG) do { if ((X)) { perror(MSG); } } while (0)
#define arrsze(X) (sizeof(X) / sizeof(*(X)))

#define __weak __attribute__((weak))

enum log_level LOG_DYNAMIC = LOG_WARN;

int __weak backend_init(int argc, char** argv) {
	(void)argc;
	(void)argv;
	return 0;
}

int __weak backend_reload(void) {
	return 0;
}

#ifdef USE_SECCOMP
int __weak backend_seccomp_rule(scmp_filter_ctx* ctx) {
	(void)ctx;
	return 0;
}
#endif

static int fd_udp;
#ifdef USE_TCP
static int fd_tcp;
#endif

static void init_sockets() {
	int optval = 1;
	struct sockaddr_in saddr = {
		.sin_family = AF_INET,
		.sin_port = htons(53),
		.sin_addr = { 0 },
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

#ifdef USE_TCP
	init_sock(tcp, SOCK_STREAM);
	chk_err(listen(fd_tcp, 0) < 0, "listen(tcp)");
#endif
#undef init_sock

#ifdef USE_BPF
	LOG(INFO, "BPF: Loading\n");
	struct sock_filter filter_udp[] = {
#include "bpf_udp.inc"
	};
	struct sock_fprog bpf_udp = {
		.len = arrsze(filter_udp),
		.filter = filter_udp,
	};
	chk_err(setsockopt(fd_udp, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_udp,
			   sizeof(bpf_udp)) < 0, "setsockopt(udp, bpf)");
	// SO_LOCK_FILTER
	LOG(INFO, "BPF: Loaded\n");
#endif
}

static int epoll_add(int epollfd, int fd, int events) {
	struct epoll_event ev = { 0 };
	ev.events = events;
	ev.data.fd = fd;
	return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
}

typedef int (*send_fn)(struct msghdr* msg, void* data);

static int handle_QUERY(struct dns_req* rq, size_t sze, send_fn cb,
			void* data) {
	struct dns_ans ans = { 0 };
	struct iovecgroup iogroup = { 0 };
	struct subdomain* q = rq->q;
	size_t q_sze = 0;

	rq->qr = 1;
	rq->aa = 1;
	rq->qdcount = ntohs(1);
	rq->ancount = ntohs(0);
	rq->arcount = ntohs(0);

	while (q->sze) {
		if ((size_t)(((char*)q) - ((char*)rq)) >= sze) {
			LOG(WARN, "Domain name longer than packet\n");
			rq->rcode = rcode_servfail;
			goto teardown;
		}
		q += q->sze + 1;
	}
	q++;
	uint16_t type = ntohs(*(uint16_t*)q);
	uint16_t class = ntohs(((uint16_t*)q)[1]);
	if (class != class_IN) {
		LOG(WARN, "Unsupported class \"%u\"\n", class);
		rq->rcode = rcode_servfail;
		goto teardown;
	}

	sze = (4 + (char*)q) - ((char*)rq);

	ans.name = htons(0xc000 | sizeof(struct dns_req));
	ans.type = htons(type);
	ans.class = htons(class);
	q_sze = (char*)q - rq->payload;
	rq->rcode = find_record(type, rq->payload, q_sze, &iogroup);

teardown:
	if (!rq->rcode && iogroup.iovlen >= 256)
		rq->rcode = rcode_servfail;

	if (rq->rcode != rcode_ok) {
		rq->ancount = ntohs(0);
		rq->arcount = ntohs(0);

		memset(&iogroup, 0, sizeof(iogroup));
	}
	struct iovec iov[1 + iogroup.iovlen * 2];
	struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = 0,
	};
#define BACK(Msg) ((Msg)->msg_iov[(Msg)->msg_iovlen++])
	BACK(&msg) = IOV(rq, sze);
	msg.msg_iov[0].iov_len = sze;
	for (size_t i = 0; i < iogroup.iovlen; i++) {
		BACK(&msg) = IOV(&ans, sizeof(ans));
		BACK(&msg) = iogroup.iovec[i];
		rq->ancount = htons(i + 1);
	}

	return cb(&msg, data);
}

static int handle_msg(struct dns_req* rq, size_t sze, send_fn cb, void* data) {
	int (*opcode_handler[])(struct dns_req*, size_t, send_fn, void*) = {
#define X(I) [opcode_##I] = handle_##I
		X(QUERY),
#undef X
	};

	if (sze < sizeof(*rq)) {
		errno = E2BIG;
		LOG(WARN, "Packet too small for struct dns_req\n");
		return cb(NULL, data);
	}

	if (rq->op >= arrsze(opcode_handler) || !opcode_handler[rq->op]) {
		errno = EINVAL;
		LOG(INFO, "unknown opcode \"%d\"\n", rq->op);
		return -1;
	}
	return opcode_handler[rq->op](rq, sze, cb, data);
}

struct data_udp {
	struct sockaddr saddr;
	socklen_t saddrlen;
	int fd;
};

static int reply_udp(struct msghdr* msg, void* data) {
	if (!msg)
		return 0;

	struct data_udp* d = data;
	msg->msg_name = &d->saddr;
	msg->msg_namelen = d->saddrlen;

	int out = sendmsg(d->fd, msg, 0);
	chk_warn(out < 0, "sendmsg(reply_udp)");
	return out;
}

#ifdef USE_TCP
static int reply_tcp(struct msghdr* msg, void* data) {
	int fd = *(int*)data;
	int out = 0;
	if (msg) {
		size_t len = 0;
		for (size_t i = 0; i < msg->msg_iovlen; i++)
			len += msg->msg_iov[i].iov_len;

		msg->msg_iov[0].iov_base -= 2;
		msg->msg_iov[0].iov_len += 2;

		*(uint16_t*)msg->msg_iov->iov_base = htons(len);

		out = sendmsg(fd, msg, 0);
		chk_warn(out < 0, "sendmsg(reply_tcp)");
	}
	chk_warn(close(fd) < 0, "close(reply_tcp)");
	return out;
}
#endif

static char* buf2hex(char* out, size_t outsze, const char* in, size_t insze) {
	out[0] = 0;
	for (size_t i = 0; i < insze && i * 2 < outsze; i++)
		sprintf(out + i * 2, "%02hhx", in[i]);
	return out;
}

#define IP_BYTES(X) ((uint8_t*)&(((struct sockaddr_in*)(X))->sin_addr.s_addr))
#ifdef USE_TCP
static void log_tcp(int fd) {
	union {
		struct sockaddr sockaddr;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} sockaddr;
	socklen_t len = sizeof(sockaddr);
	chk_warn(getpeername(fd, &sockaddr.sockaddr, &len) < 0,
		 "getpeername");

	LOG(INFO, "tcp msg from: %hhu.%hhu.%hhu.%hhu:%hu (family:%d)\n",
	     IP_BYTES(&sockaddr)[0],
	     IP_BYTES(&sockaddr)[1],
	     IP_BYTES(&sockaddr)[2],
	     IP_BYTES(&sockaddr)[3],
	     sockaddr.in.sin_port,
	     sockaddr.sockaddr.sa_family);
}
#endif

static void dns_iter(int fd) {
	char buf[1024];
	char* ptr = buf;
	ssize_t sze = 0;

	union {
		struct data_udp udp;
		int fd;
	} data;
	send_fn fn;

#ifdef USE_TCP
	if (fd == fd_udp)
#endif
	{
		data.udp.saddrlen = sizeof(data.udp.saddr);
		data.udp.fd = fd_udp;
		sze = recvfrom(fd_udp, buf, sizeof(buf), MSG_DONTWAIT,
			       &data.udp.saddr, &data.udp.saddrlen);
		chk_warn(sze < 0, "recvfrom");
		fn = reply_udp;
		LOG(INFO, "udp msg from: %hhu.%hhu.%hhu.%hhu:%hu (family:%d)\n",
			  IP_BYTES(&data.udp.saddr)[0],
			  IP_BYTES(&data.udp.saddr)[1],
			  IP_BYTES(&data.udp.saddr)[2],
			  IP_BYTES(&data.udp.saddr)[3],
			  ((struct sockaddr_in*)&data.udp.saddr)->sin_port,
			  data.udp.saddr.sa_family);
	}
#ifdef USE_TCP
	else {
		sze = recv(fd, buf, sizeof(buf), 0);
		chk_warn(sze < 0, "recv");
		if (sze >= 2) {
			ssize_t sze_tmp = ntohs(*(uint16_t*)buf);
			ptr += 2;
			if (sze_tmp > sze)
				sze = 0;
			else
				sze = sze_tmp;
		} else {
			sze = 0;
		}
		data.fd = fd;
		fn = reply_tcp;
		log_tcp(fd);
	}
#endif

	char hexbuf[sze * 2 + 1];
	LOG(INFO, "msg received (%s): \"%s\"\n", fd == fd_udp ? "udp" : "tcp",
	    buf2hex(hexbuf, sizeof(hexbuf), buf, sze));

	chk_warn(handle_msg((void*)ptr, sze, fn, &data) < 0, "handle_msg");
}

#ifdef USE_TCP
static void dns_new_tcp(int efd) {
	int afd = accept(fd_tcp, NULL, 0);
	chk_warn(afd < 0, "accept");
	chk_warn(epoll_add(efd, afd, EPOLLIN|EPOLLET) < 0, "epoll_add");
}
#endif

static void dns_loop(int efd) {
	struct epoll_event ev[16];
	int nfds = epoll_wait(efd, ev, arrsze(ev), -1);
	if (nfds < 0 && errno == EINTR)
		return;
	chk_err(nfds < 0, "epoll_wait");

	for (int i = 0; i < nfds; i++) {
#ifdef USE_TCP
		if (ev[i].data.fd == fd_tcp)
			dns_new_tcp(efd);
		else
#endif
			dns_iter(ev[i].data.fd);
	}
}

static void sighup_handler(int s) {
	(void)s;
	LOG(INFO, "reloading config: started\n");
	backend_reload();
	LOG(INFO, "reloading config: finish\n");
}

static void set_verbosity(void) {
	const char* verbosity = getenv("DNS_VERBOSITY");
	if (!verbosity)
		return;

	if (!strcasecmp(verbosity, "INFO")) {
		LOG_DYNAMIC = LOG_INFO;
	} else if (!strcasecmp(verbosity, "WARN")) {
		LOG_DYNAMIC = LOG_WARN;
	} else if (!strcasecmp(verbosity, "ERR")) {
		LOG_DYNAMIC = LOG_ERR;
	} else {
		LOG(ERR, "Unsupported verbosity \"%s\"\n", verbosity);
		exit(1);
	}
}

int main(int argc, char** argv) {
	int dry_run = 0;
	if (argc >= 2 && !strcmp(argv[1], "--dry-run")) {
		dry_run = 1;
		argc--;
		argv++;
	}

	set_verbosity();

	if (backend_init(argc, argv) < 0)
		return 1;

	if (dry_run)
		return 0;

	signal(SIGHUP, sighup_handler);

	init_sockets();

	int efd = epoll_create1(0);
	chk_err(efd < 0, "epoll_create1");

	chk_err(epoll_add(efd, fd_udp, EPOLLIN) < 0, "epoll_add");
#ifdef USE_TCP
	chk_err(epoll_add(efd, fd_tcp, EPOLLIN) < 0, "epoll_add");
#endif

	// TODO: Drop capabilities

#ifdef USE_SECCOMP
	scmp_filter_ctx ctx;
	chk_err(!(ctx = seccomp_init(SCMP_ACT_KILL)), "seccomp_init");

#define X(S) chk_err(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(S), 0) < 0,\
		     "seccomp_rule_add(" #S ")");
	X(accept); X(close); X(epoll_ctl); X(epoll_pwait); X(epoll_wait);
	X(recv); X(recvfrom); X(sendmsg); X(write); X(rt_sigreturn);
	X(exit_group);

	X(getpeername);
#undef X
	chk_err(backend_seccomp_rule(&ctx) < 0, "backend_seccomp_rule");
	chk_err(seccomp_load(ctx) < 0, "seccomp_load");
#endif

	while (1)
		dns_loop(efd);
}
