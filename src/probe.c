#include "probe.h"
#include "alert.h"
#include "arp.h"
#include "conflict.h"
#include "decide.h"
#include "history.h"
#include "iface.h"
#include "mac.h"
#include "timing.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>

#define PROBE_NUM 3
#define PROBE_WAIT_S 1
#define PROBE_MIN_S 1
#define PROBE_MAX_S 2
#define ANNOUNCE_WAIT_S 2

static int on_conflict(struct history *h, const char *ifname, uint32_t ip,
                       const struct arp_msg *m, const struct accept *acc) {
	struct conflicts cs;
	enum alert_kind kind;
	char sha[18], src[18];

	conflicts_init(&cs, 0, 0);
	if (history_begin(h, &cs, now_ms()) < 0)
		return 1;
	conflict_probe(&cs, ip, m->sha, m->src, now_ms(), &kind);
	history_commit(h, &cs);

	if (kind != ALERT_NONE) {
		enum action act;
		const struct alert_def *def = decide_alert(alert_case(kind), acc, &act);
		struct alert a;
		char line[1024];
		alert_init(&a, def->kase);
		decide_probe_info(&a, kind, &cs, ip, m);
		if (alert_format(line, sizeof(line), &a, act, ifname, wall_ms()) == 0)
			fprintf(stderr, "%s\n", line);
		if (act == ACT_STOP)
			return ALERT_CODE;
	}
	printf("taken mac %s src %s\n", mac_format(m->sha, sha),
	       mac_format(m->src, src));
	return 0;
}

static int probe_loop(int fd, int ifindex, const unsigned char mine[ETH_ALEN],
                      struct history *h, const char *ifname, uint32_t ip,
                      const struct accept *acc) {
	int probes = 0;
	uint64_t deadline = now_ms() + random_ms(0, scaled_ms(PROBE_WAIT_S));

	for (;;) {
		uint64_t now = now_ms();
		if (now >= deadline) {
			if (probes == PROBE_NUM) {
				printf("free\n");
				return 0;
			}
			if (arp_request(fd, ifindex, mine, 0, ip) < 0)
				return 1;
			probes++;
			if (probes < PROBE_NUM)
				deadline = now + random_ms(scaled_ms(PROBE_MIN_S),
				                           scaled_ms(PROBE_MAX_S));
			else
				deadline = now + scaled_ms(ANNOUNCE_WAIT_S);
			continue;
		}

		struct pollfd p = {.fd = fd, .events = POLLIN};
		int r = poll(&p, 1, (int)(deadline - now));
		if (r < 0) {
			if (errno == EINTR)
				continue;
			perror("poll error");
			return 1;
		}
		if (r == 0)
			continue;

		struct arp_msg m;
		int n;
		while ((n = arp_read(fd, &m)) > 0)
			if (decide_probe_conflict(&m, ip, mine))
				return on_conflict(h, ifname, ip, &m, acc);
		if (n < 0)
			return 1;
	}
}

int probe_run(const char *ifname, uint32_t ip, const struct accept *acc) {
	int ifindex;
	unsigned char mine[ETH_ALEN];
	struct history h;

	if (iface_lookup(ifname, &ifindex, mine) < 0)
		return 1;
	if (history_make_dirs() < 0 || history_open(&h, HISTORY_DIR, ifname) < 0)
		return 1;
	int fd = arp_open(ifindex);
	if (fd < 0) {
		history_close(&h);
		return 1;
	}

	int ret = probe_loop(fd, ifindex, mine, &h, ifname, ip, acc);
	close(fd);
	history_close(&h);
	return ret;
}
