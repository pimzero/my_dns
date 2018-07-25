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
	uint16_t record_len;
	char* name;
	struct record* record;
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

	if (!strcmp("A", s)) {
		e->type = type_A;

		s = strtok_r(NULL, delim, &saveptr);
		e->name = strdup(s);
		if (!e->name)
			return -1;

		s = strtok_r(NULL, delim, &saveptr);
		errno = 0;
		long ttl_long = strtol(s, NULL, 0);
		if (errno) {
			perror("strtol");
			return -1;
		}
		e->record = malloc(24);
		if (!e->name)
			return -1;

		e->record_len = 4 + 2 + 4;

		s = strtok_r(NULL, delim, &saveptr);
		sscanf(s, "%hhd.%hhd.%hhd.%hhd",
		       e->record->payload,
		       e->record->payload + 1,
		       e->record->payload + 2,
		       e->record->payload + 3);
		e->record->ttl = htonl(ttl_long);
		e->record->len = htons(4);

		err = 0;
	}

	free(tmpstr);
	return err;
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

		entries.count++;
		entries.table = realloc(entries.table,
					entries.count * sizeof(*entries.table));
		memset(&entries.table[entries.count - 1], 0, sizeof(*entries.table));
		if (parse_line(line, &entries.table[entries.count - 1]) < 0) {
			log(ERR, "Could not parse line \"%s\"\n", line);
			return - 1;
		}
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
	log(WARN, "reloading\n");
	for (size_t i = 0; i < entries.count; i++) {
		free(entries.table[i].name);
		free(entries.table[i].record);
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

int find_record(enum type type, void* buf, size_t sze, struct iovec* iov) {
	char name[256];
	*iov = IOV(NULL, 0);
	if (record_to_str(name, sizeof(name), buf, sze) < 0) {
		log(ERR, "record_to_str failed\n");
		return rcode_servfail;
	}

	for (size_t i = 0; i < entries.count; i++) {
		if (entries.table[i].type == type &&
		    !strcasecmp(entries.table[i].name, name)) {
			log(INFO, "Found: \"%s\"\n", name);
			*iov = IOV(entries.table[i].record,
				   entries.table[i].record_len);
			break;
		}
	}
	if (!iov->iov_base) {
		log(INFO, "Not found: \"%s\"\n", name);
		return rcode_nxdomain;
	}
	return rcode_ok;
}
