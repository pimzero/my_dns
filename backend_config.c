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

static const char* fname;

struct parse_elt {
	size_t sze;
	void* data;
};

static struct parse_elt parse_U16(char** saveptr) {
	struct parse_elt out = { 0 };
	errno = 0;
	uint16_t* i = malloc(sizeof(*i));
	char* s = strtok_r(NULL, " ", saveptr);
	*i = htons(strtol(s, NULL, 0));
	if (errno) {
		perror("strtol");
		return out;
	}
	out.sze = sizeof(*i);
	out.data = i;

	return out;
}

static struct parse_elt parse_U32(char** saveptr) {
	struct parse_elt out = { 0 };
	errno = 0;
	uint32_t* i = malloc(sizeof(*i));
	char* s = strtok_r(NULL, " ", saveptr);
	*i = htonl(strtol(s, NULL, 0));
	if (errno) {
		perror("strtol");
		return out;
	}
	out.sze = sizeof(*i);
	out.data = i;

	return out;
}

static struct parse_elt parse_IPV4(char** saveptr) {
	struct parse_elt out = { 0 };
	out.sze = 4;
	out.data = malloc(out.sze);

	char* s = strtok_r(NULL, " ", saveptr);
	if (!s)
		s = "";
	if (inet_pton(AF_INET, s, out.data) != 1) {
		log(ERR, "inet_pton failed (ipv4) \"%s\"\n", s);
		free(out.data);
		out.data = NULL;
	}

	return out;
}

static struct parse_elt parse_IPV6(char** saveptr) {
	struct parse_elt out = { 0 };
	out.sze = 16;
	out.data = malloc(out.sze);

	char* s = strtok_r(NULL, " ", saveptr);
	if (!s)
		s = "";
	if (inet_pton(AF_INET6, s, out.data) != 1) {
		log(ERR, "inet_pton failed (ipv4)\n");
		free(out.data);
		out.data = NULL;
	}

	return out;
}

static struct parse_elt parse_TXT(char** saveptr) {
	struct parse_elt out = { 0 };

	char* s = strtok_r(NULL, "", saveptr);
	if (!s)
		s = "";
	size_t sze = strlen(s);
	if (sze > 255) {
		log(ERR, "TXT: string to long\n");
		out.data = NULL;
		return out;
	}
	out.sze = sze + 1;
	out.data = malloc(out.sze + 1);
	((char*)out.data)[0] = sze;
	memcpy(((char*)out.data) + 1, s, sze);

	return out;
}

static struct parse_elt parse_DOMAIN(char** saveptr) {
	struct parse_elt out = { 0 };

	char* s = strtok_r(NULL, " ", saveptr);
	if (s == NULL)
		s = "";
	size_t len = strlen(s);
	if (len > 255) {
		log(ERR, "Domain too long\n");
		return out;
	}
	out.data = malloc(len + 2);
	char* saveptr2 = NULL;
	s = strtok_r(s, ".", &saveptr2);
	if (!s)
		s = "";
	if (strlen(s) == 0)
		len--;
	char* cur = out.data;
	do {
		*cur = strlen(s);
		strcpy(cur + 1, s);
		cur += *cur + 1;
		*cur = 0;
	} while ((s = strtok_r(NULL, ".", &saveptr2)));
	out.sze = len + 1;

	return out;
}

#define arrsze(X) (sizeof(X) / sizeof(*(X)))

enum parser_part {
	part_U16,
	part_U32,
	part_IPV4,
	part_IPV6,
	part_TXT,
	part_DOMAIN,
};

static int parse_eval(enum parser_part* p, size_t sze, struct entry* e,
		      char** saveptr) {
	size_t record_len = 0;
	struct parse_elt pe[sze];
	struct parse_elt (*f_arr[])(char**) = {
#if 1
#define X(X) [part_##X] = parse_##X
		X(U16),
		X(U32),
		X(IPV4),
		X(IPV6),
		X(TXT),
		X(DOMAIN),
#undef X
#endif
	};
	struct parse_elt ttl = parse_U32(saveptr);
	if (!ttl.data)
		return -1;
	for (size_t i = 0; i < arrsze(pe); i++)
		pe[i] = f_arr[p[i]](saveptr);
	char* still_to_read = strtok_r(NULL, "", saveptr);
	if (still_to_read) {
		log(ERR, "Too much for record: \"%s\"\n", still_to_read);
		return -1;
	}
	for (size_t i = 0; i < arrsze(pe); i++) {
		if (!pe[i].data)
			return -1;
		record_len += pe[i].sze;
	}

	struct record* record = malloc(record_len + sizeof(*record));

	size_t pos = 0;
	for (size_t i = 0; i < arrsze(pe); i++) {
		memcpy(&record->payload[pos], pe[i].data, pe[i].sze);
		pos += pe[i].sze;
		free(pe[i].data);
	}

	if (!e->name)
		return -1;

	record->ttl = *(uint32_t*)ttl.data;
	free(ttl.data);
	record->len = htons(record_len);
	e->count = 1;
	e->iovec = malloc(sizeof(*e->iovec));
	e->iovec->iov_base = record;
	e->iovec->iov_len = record_len + sizeof(*record);

	return 0;
}

static int parse_line(char* str, struct entry* e) {
	char* saveptr = NULL;
	char* s;

	s = strtok_r(str, " ", &saveptr);

	e->type = -1;
#define SET_TYPE(X) do { if (!strcasecmp(#X, s)) e->type = type_##X; } while (0)
	SET_TYPE(A);
	SET_TYPE(AAAA);
	SET_TYPE(MX);
	SET_TYPE(TXT);
	SET_TYPE(CNAME);
	SET_TYPE(SRV);
	SET_TYPE(SOA);
	SET_TYPE(PTR);
	SET_TYPE(NS);
#undef SET_TYPE

	struct parse_elt domain_elt = parse_DOMAIN(&saveptr);
	if (!domain_elt.data)
		return -1;
	e->name = domain_elt.data;

	if (e->type == type_A) {
		enum parser_part parts[] = { part_IPV4 };
		return parse_eval(parts, arrsze(parts), e, &saveptr);
	} else if (e->type == type_AAAA) {
		enum parser_part parts[] = { part_IPV6 };
		return parse_eval(parts, arrsze(parts), e, &saveptr);
	} else if (e->type == type_TXT) {
		enum parser_part parts[] = { part_TXT };
		return parse_eval(parts, arrsze(parts), e, &saveptr);
	} else if (e->type == type_MX) {
		enum parser_part parts[] = { part_U16, part_DOMAIN };
		return parse_eval(parts, arrsze(parts), e, &saveptr);
	} else if (e->type == type_CNAME) {
		enum parser_part parts[] = { part_DOMAIN };
		return parse_eval(parts, arrsze(parts), e, &saveptr);
	} else if (e->type == type_SRV) {
		enum parser_part parts[] = { part_U16, part_U16, part_U16,
					     part_DOMAIN };
		return parse_eval(parts, arrsze(parts), e, &saveptr);
	} else if (e->type == type_SOA) {
		enum parser_part parts[] = { part_DOMAIN, part_DOMAIN, part_U32,
					     part_U32, part_U32, part_U32,
					     part_U32 };
		return parse_eval(parts, arrsze(parts), e, &saveptr);
	} else if (e->type == type_PTR) {
		enum parser_part parts[] = { part_DOMAIN };
		return parse_eval(parts, arrsze(parts), e, &saveptr);
	} else if (e->type == type_NS) {
		enum parser_part parts[] = { part_DOMAIN };
		return parse_eval(parts, arrsze(parts), e, &saveptr);
	}
	log(ERR, "Unknown type\n");
	return -1;
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

	return 0;
}

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
		char* tmpline = strdup(line);
		if (parse_line(tmpline, &entry) < 0) {
			log(ERR, "Could not parse line \"%s\"\n", line);
			return - 1;
		}
		free(tmpline);
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

int find_record(enum type type, void* buf, size_t sze, struct iovecgroup* io) {
	io->iovlen = 0;
	for (size_t i = 0; i < entries.count; i++) {
		if (entries.table[i].type == type &&
		    !strncasecmp(entries.table[i].name, buf, sze)) {
			log(INFO, "Found: \"%.*s\" (%d)\n", (int)sze,
			    (char*)buf, type);
			io->iovlen = entries.table[i].count;
			io->iovec = entries.table[i].iovec;
			break;
		}
	}
	if (!io->iovlen) {
		log(INFO, "Not found: \"%.*s\" (%d)\n", (int)sze, (char*)buf,
		    type);
		return rcode_nxdomain;
	}
	return rcode_ok;
}
