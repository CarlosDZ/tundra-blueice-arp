#include "history.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define RUN_DIR "/run/tundra"
#define BLUEICE_DIR RUN_DIR "/blueice"

enum {
	K_AT = 1,
	K_ADDR = 2,
	K_MAC = 4,
	K_BOUND = 8,
	K_FORGED = 16,
	K_ALL = 31
};

#define LINE_MAX_LEN 256
#define RECORD_MAX_LEN 96

static int make_dir(const char *path, mode_t mode) {
	if (mkdir(path, mode) < 0 && errno != EEXIST) {
		perror("mkdir error");
		return -1;
	}
	return 0;
}

int history_make_dirs(void) {
	if (make_dir(RUN_DIR, 0755) < 0 || make_dir(BLUEICE_DIR, 0700) < 0 ||
	    make_dir(HISTORY_DIR, 0700) < 0)
		return -1;
	return 0;
}

int history_open(struct history *h, const char *dir, const char *ifname) {
	char path[256], lock[256];
	h->fd = -1;
	h->lockfd = -1;
	int n = snprintf(path, sizeof(path), "%s/%s", dir, ifname);
	int m = snprintf(lock, sizeof(lock), "%s/%s.lock", dir, ifname);
	if (n < 0 || m < 0 || (size_t)n >= sizeof(path) ||
	    (size_t)m >= sizeof(lock)) {
		fprintf(stderr, "history path too long\n");
		return -1;
	}
	h->lockfd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	h->fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (h->lockfd < 0 || h->fd < 0) {
		perror("open error");
		history_close(h);
		return -1;
	}
	return 0;
}

void history_close(struct history *h) {
	if (h->fd >= 0)
		close(h->fd);
	if (h->lockfd >= 0)
		close(h->lockfd);
	h->fd = -1;
	h->lockfd = -1;
}

int history_begin(struct history *h, struct conflicts *cs, uint64_t now) {
	while (flock(h->lockfd, LOCK_EX) < 0) {
		if (errno != EINTR) {
			perror("flock error");
			return -1;
		}
	}
	history_load(h->fd, cs, now);
	return 0;
}

int history_commit(struct history *h, const struct conflicts *cs) {
	int r = history_save(h->fd, cs);
	flock(h->lockfd, LOCK_UN);
	return r;
}

static int parse_bit(const char *s, int *out) {
	if ((s[0] != '0' && s[0] != '1') || s[1] != '\0')
		return -1;
	*out = s[0] - '0';
	return 0;
}

static int parse_mac(const char *s, unsigned char mac[ETH_ALEN]) {
	unsigned int b[ETH_ALEN];
	char end;
	if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c", &b[0], &b[1], &b[2], &b[3],
	           &b[4], &b[5], &end) != ETH_ALEN)
		return -1;
	for (int i = 0; i < ETH_ALEN; i++)
		mac[i] = (unsigned char)b[i];
	return 0;
}

static int parse_at(const char *s, uint64_t *out) {
	if (s[0] < '0' || s[0] > '9')
		return -1;
	char *end;
	errno = 0;
	unsigned long long v = strtoull(s, &end, 10);
	if (errno || *end != '\0')
		return -1;
	*out = v;
	return 0;
}

static int parse_line(char *line, struct conflict *c) {
	int seen = 0;
	char *save = NULL;
	memset(c, 0, sizeof(*c));

	for (char *key = strtok_r(line, " ", &save); key;
	     key = strtok_r(NULL, " ", &save)) {
		char *val = strtok_r(NULL, " ", &save);
		struct in_addr a;
		int r = 0;
		if (!val)
			return -1;
		if (strcmp(key, "at") == 0) {
			r = parse_at(val, &c->at);
			seen |= K_AT;
		} else if (strcmp(key, "addr") == 0) {
			r = inet_pton(AF_INET, val, &a) == 1 ? 0 : -1;
			c->addr = a.s_addr;
			seen |= K_ADDR;
		} else if (strcmp(key, "mac") == 0) {
			r = parse_mac(val, c->mac);
			seen |= K_MAC;
		} else if (strcmp(key, "bound") == 0) {
			r = parse_bit(val, &c->bound);
			seen |= K_BOUND;
		} else if (strcmp(key, "forged") == 0) {
			r = parse_bit(val, &c->forged);
			seen |= K_FORGED;
		}
		if (r < 0)
			return -1;
	}
	return seen == K_ALL ? 0 : -1;
}

static void add_line(char *line, struct conflicts *cs, uint64_t now) {
	struct conflict c;
	if (parse_line(line, &c) < 0 || c.at > now ||
	    now - c.at >= CONFLICT_WINDOW_MS)
		return;
	if (cs->n == CONFLICT_MAX) {
		memmove(&cs->recs[0], &cs->recs[1],
		        (CONFLICT_MAX - 1) * sizeof(cs->recs[0]));
		cs->n--;
	}
	cs->recs[cs->n++] = c;
}

int history_load(int fd, struct conflicts *cs, uint64_t now) {
	char buf[LINE_MAX_LEN];
	size_t have = 0;
	off_t off = 0;
	int skip = 0;

	cs->n = 0;
	for (;;) {
		ssize_t n = pread(fd, buf + have, sizeof(buf) - have, off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return 0;
		off += n;
		have += (size_t)n;

		char *start = buf, *nl;
		while ((nl = memchr(start, '\n', (size_t)(buf + have - start)))) {
			*nl = '\0';
			if (!skip)
				add_line(start, cs, now);
			skip = 0;
			start = nl + 1;
		}
		have = (size_t)(buf + have - start);
		memmove(buf, start, have);
		if (have == sizeof(buf)) {
			have = 0;
			skip = 1;
		}
	}
}

static int write_all(int fd, const char *buf, size_t len) {
	size_t done = 0;
	while (done < len) {
		ssize_t n = pwrite(fd, buf + done, len - done, (off_t)done);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		done += (size_t)n;
	}
	return 0;
}

int history_save(int fd, const struct conflicts *cs) {
	char out[CONFLICT_MAX * RECORD_MAX_LEN];
	size_t len = 0;

	for (int i = 0; i < cs->n; i++) {
		const struct conflict *c = &cs->recs[i];
		char a[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &c->addr, a, sizeof(a));
		int n = snprintf(
		    out + len, sizeof(out) - len,
		    "at %llu addr %s mac %02x:%02x:%02x:%02x:%02x:%02x bound %d "
		    "forged %d\n",
		    (unsigned long long)c->at, a, c->mac[0], c->mac[1], c->mac[2],
		    c->mac[3], c->mac[4], c->mac[5], c->bound, c->forged);
		if (n < 0 || (size_t)n >= sizeof(out) - len)
			return -1;
		len += (size_t)n;
	}

	/* Rewritten in place through the descriptor opened at start: after the
	 * lockdown no file can be opened or renamed. A torn write leaves lines
	 * that history_load drops. */
	if (write_all(fd, out, len) < 0 || ftruncate(fd, (off_t)len) < 0) {
		perror("write error");
		return -1;
	}
	return 0;
}
