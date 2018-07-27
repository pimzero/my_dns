#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>

#include "dns.h"

#define log(X, ...) LOG(X, "backend: " __VA_ARGS__);

#define IP(A, B, C, D) ((A) | ((B) << 8) | ((C) << 16) | ((D) << 24))

struct entry {
	enum type type;
	uint16_t count;
	char* name;
	struct iovec* iovec;
} __packed;

static struct {
	struct entry* table;
	size_t count;
} entries;

const char* fname;

static int parse_line(const char* str, struct entry* e) {
	char* saveptr = NULL;
	char* s;
	char* delim = " ";

	int err = -1;
	char* tmpstr = strdup(str);
	s = strtok_r(tmpstr, delim, &saveptr);

	if (!strcmp("A", s) || !strcmp("AAAA", s)) {
		if (!strcmp("A", s))
			e->type = type_A;
		else
			e->type = type_AAAA;

		s = strtok_r(NULL, delim, &saveptr);
		e->name = strdup(s);
		if (!e->name)
			return -1;

		s = strtok_r(NULL, delim, &saveptr);
		size_t record_len = sizeof(struct record) +
			            (e->type == type_A ? 4 : 16);
		struct record* record = malloc(record_len + 14);

		errno = 0;
		record->ttl = htonl(strtol(s, NULL, 0));
		if (errno) {
			perror("strtol");
			return -1;
		}

		if (!e->name)
			return -1;

		s = strtok_r(NULL, delim, &saveptr);
		inet_pton(e->type == type_A ? AF_INET : AF_INET6, s,
			  record->payload);
		record->len = htons(e->type == type_A ? 4 : 16);
		e->count = 1;
		e->iovec = malloc(sizeof(*e->iovec));
		e->iovec->iov_base = record;
		e->iovec->iov_len = record_len;

		err = 0;
	}

	free(tmpstr);
	return err;
}

static int insert_entry(struct entry* e) {
	for (size_t i = 0; i < entries.count; i++) {
		if (entries.table[i].type == e->type &&
		    !strcmp(entries.table[i].name, e->name)) {
			struct entry* dst = &entries.table[i];
			dst->count++;
			dst->iovec = realloc(dst->iovec,
					     dst->count * sizeof(struct iovec));
			dst->iovec[dst->count-1].iov_base = e->iovec->iov_base;
			dst->iovec[dst->count-1].iov_len = e->iovec->iov_len;

			free(e->name);
			free(e->iovec);

			return 0;
		}
	}

	entries.count++;
	entries.table = realloc(entries.table,
			entries.count * sizeof(*entries.table));
	memcpy(&entries.table[entries.count - 1], e, sizeof(*e));
	log(INFO, "XX%dXX\n", e->count);

	return 0;
};

static int load_file(FILE* file) {
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	while ((nread = getline(&line, &len, file)) != -1) {
		if (nread > 0 && line[nread - 1] == '\n')
			line[nread - 1] = '\0';

		// comment line start with '#'
		if (*line == '#' || *line == '\0')
			continue;

		struct entry entry = { 0 };
		if (parse_line(line, &entry) < 0) {
			log(ERR, "Could not parse line \"%s\"\n", line);
			return - 1;
		}
		insert_entry(&entry);
	}
	free(line);

	return 0;
}

const char* ro_strdup(const char* str) {
	void* out = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
			 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (out == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}

	strncpy(out, str, 4095);

	if (mprotect(out, 4096, PROT_READ) < 0) {
		perror("mprotect");
		return NULL;
	}
	return out;
}

int backend_init(int argc, char** argv) {
	if (argc < 2) {
		log(ERR, "Not enough arguments\n");
		return -1;
	}

	fname = ro_strdup(argv[1]);
	FILE* file = fopen(fname, "r");
	if (!file) {
		perror("fopen");
		return -1;
	}

	int ret = load_file(file);
	fclose(file);

	log(INFO, "Initialized\n");
	return ret;
}

int backend_reload(void) {
	for (size_t i = 0; i < entries.count; i++) {
		free(entries.table[i].name);
		for (size_t j = 0; j < entries.table[i].count; j++)
			free(entries.table[i].iovec[j].iov_base);
		free(entries.table[i].iovec);
	}
	entries.count = 0;
	FILE* file = fopen(fname, "r");
	if (load_file(file) < 0) {
		log(ERR, "load_file failed\n");
		exit(1);
	}
	fclose(file);
	log(INFO, "reloaded\n");
	return 0;
}

#ifdef USE_SECCOMP
int backend_seccomp_rule(scmp_filter_ctx* ctx) {
	if (seccomp_rule_add(*ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0) < 0)
		return -1;
	if (seccomp_rule_add(*ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0)
		return -1;
	if (seccomp_rule_add(*ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 2,
			     SCMP_A1(SCMP_CMP_EQ, (ptrdiff_t)fname),
			     SCMP_A2(SCMP_CMP_EQ, O_RDONLY)) < 0)
		return -1;
	if (seccomp_rule_add(*ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0)
		return -1;
	return 0;
}
#endif

static int record_to_str(char* out, size_t sze_out, void* in, size_t sze_in) {
	if (sze_in > sze_out)
		return -1;

	if (!*(uint8_t*)in) {
		out[0] = '.';
		out[1] = '\0';
	}

	while (*(uint8_t*)in) {
		struct {
			uint8_t sze;
			char data[0];
		} __packed *cur = in;

		if (cur->sze + 1 > sze_out)
			return -1;

		memcpy(out, cur->data, cur->sze);
		sze_out -= cur->sze + 1;
		out[cur->sze] = '.';
		out += cur->sze + 1;
		in += cur->sze + 1;
		*out = 0;
	}
	return 0;
}

int find_record(enum type type, void* buf, size_t sze, struct iovecgroup* io) {
	char name[256];
	if (record_to_str(name, sizeof(name), buf, sze) < 0) {
		log(ERR, "record_to_str failed\n");
		return rcode_servfail;
	}

	io->iovlen = 0;
	for (size_t i = 0; i < entries.count; i++) {
		if (entries.table[i].type == type &&
		    !strcasecmp(entries.table[i].name, name)) {
			log(INFO, "Found: \"%s\"\n", name);
			io->iovlen = entries.table[i].count;
			io->iovec = entries.table[i].iovec;
			log(INFO, ">>%zu<<\n", io->iovlen);
			break;
		}
	}
	if (!io->iovlen) {
		log(INFO, "Not found: \"%s\" (%d)\n", name, type);
		return rcode_nxdomain;
	}
	return rcode_ok;
}
