#include "watch.h"
#include "alert.h"
#include "arp.h"
#include "conflict.h"
#include "decide.h"
#include "emit.h"
#include "gateway.h"
#include "history.h"
#include "iface.h"
#include "lockdown.h"
#include "mac.h"
#include "timing.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/signalfd.h>
#include <unistd.h>

#define ANNOUNCE_NUM 2
#define ANNOUNCE_INTERVAL_S 2
#define DEFEND_INTERVAL_S 10
#define DOWN_CHECK_MS 1000

struct watch {
	const char *ifname;
	int ifindex;
	unsigned char mine[ETH_ALEN];
	uint32_t ip;
	uint32_t gw;
	const struct accept *acc;
	struct history h;
	struct conflicts cs;
	struct gateway g;
	struct warned warned;
	int fd;
	int down;
	int announces;
	uint64_t announce_at;
};

static const char *ip_str(uint32_t a, char buf[INET_ADDRSTRLEN]) {
	return inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN);
}

static void announce(struct watch *w) {
	arp_request(w->fd, w->ifindex, w->mine, w->ip, w->ip);
}

static int report(struct watch *w, struct alert *a,
                  const unsigned char mac[ETH_ALEN]) {
	enum action act;
	decide_alert(a->def->kase, w->acc, &act);
	if (act == ACT_STOP) {
		emit_alert(a, act, w->ifname);
		return ALERT_CODE;
	}
	if (decide_warn_once(&w->warned, a->def->kase, mac))
		emit_alert(a, act, w->ifname);
	return -1;
}

static int on_addr(struct watch *w, const struct arp_msg *m) {
	char ip[INET_ADDRSTRLEN], mac[18];
	enum alert_kind kind;

	if (history_begin(&w->h, &w->cs, now_ms()) < 0)
		return 1;
	enum verdict v =
	    conflict_claim(&w->cs, w->ip, m->sha, m->src, now_ms(), &kind);
	history_commit(&w->h, &w->cs);

	if (kind != ALERT_NONE) {
		struct alert a;
		alert_init(&a, alert_case(kind));
		decide_addr_info(&a, kind, &w->cs, w->ip, m);
		int r = report(w, &a, m->sha);
		if (r >= 0)
			return r;
	}

	ip_str(w->ip, ip);
	mac_format(m->sha, mac);
	switch (v) {
	case V_DEFEND:
		announce(w);
		printf("defending address %s against %s\n", ip, mac);
		return -1;
	case V_HOLD:
		printf("address %s claimed by %s, holding it\n", ip, mac);
		return -1;
	case V_GIVE_UP:
		break;
	}
	printf("conflict addr %s mac %s\n", ip, mac);
	return 1;
}

static int gw_alert(struct watch *w, const char *kase,
                    const struct arp_msg *invalid,
                    const unsigned char mac[ETH_ALEN]) {
	struct alert a;
	alert_init(&a, kase);
	decide_gw_info(&a, &w->g, w->gw, invalid);
	return report(w, &a, mac);
}

static int on_gw(struct watch *w, const struct arp_msg *m) {
	switch (gateway_reply(&w->g, m->sha, m->src)) {
	case GW_IMPERSONATED:
		return gw_alert(w, "D", NULL, m->sha);
	case GW_INVALID_MAC:
		return gw_alert(w, "mac-gw", m, m->sha);
	case GW_NONE:
	case GW_LEARNED:
		break;
	}
	return -1;
}

static int on_settle(struct watch *w) {
	char mac[18];
	switch (gateway_settle(&w->g)) {
	case GW_LEARNED:
		printf("gateway is at %s\n", mac_format(w->g.mac, mac));
		return -1;
	case GW_IMPERSONATED:
		return gw_alert(w, "D", NULL, w->g.seen[w->g.nseen - 1]);
	case GW_NONE:
	case GW_INVALID_MAC:
		break;
	}
	return -1;
}

static int on_net(struct watch *w, const struct arp_msg *m) {
	struct alert a;
	alert_init(&a, "mac-net");
	decide_net_info(&a, m);
	return report(w, &a, m->sha);
}

static int on_arp(struct watch *w) {
	struct arp_msg m;
	int n;
	while ((n = arp_read(w->fd, &m)) > 0) {
		int r = -1;
		w->down = 0;
		switch (decide_watch_target(&m, w->ip, w->gw, w->mine)) {
		case T_ADDR:
			r = on_addr(w, &m);
			break;
		case T_GW:
			r = on_gw(w, &m);
			break;
		case T_NET:
			r = on_net(w, &m);
			break;
		case T_NONE:
			break;
		}
		if (r >= 0)
			return r;
	}
	if (n == 0)
		return -1;
	if (errno != ENETDOWN)
		return 1;
	w->down = 1;
	return -1;
}

static int check_down(const struct watch *w) {
	if (!w->down || iface_alive(w->fd, w->ifname, w->ifindex))
		return -1;
	fprintf(stderr, "interface %s removed\n", w->ifname);
	return 1;
}

static int open_signals(void) {
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("sigprocmask error");
		return -1;
	}
	int fd = signalfd(-1, &mask, SFD_CLOEXEC);
	if (fd < 0)
		perror("signalfd error");
	return fd;
}

static int next_timeout(const struct watch *w, uint64_t now) {
	uint64_t next = UINT64_MAX;
	if (w->announces < ANNOUNCE_NUM)
		next = w->announce_at;
	if (w->g.until && w->g.until < next)
		next = w->g.until;
	if (w->down && now + DOWN_CHECK_MS < next)
		next = now + DOWN_CHECK_MS;
	if (next == UINT64_MAX)
		return -1;
	return next > now ? (int)(next - now) : 0;
}

static int loop(struct watch *w, int sfd) {
	for (;;) {
		uint64_t now = now_ms();
		if (gateway_due(&w->g, now)) {
			int r = on_settle(w);
			if (r >= 0)
				return r;
			continue;
		}
		if (w->announces < ANNOUNCE_NUM && now >= w->announce_at) {
			announce(w);
			w->announces++;
			w->announce_at = now + scaled_ms(ANNOUNCE_INTERVAL_S);
			continue;
		}

		struct pollfd pfd[2] = {{.fd = sfd, .events = POLLIN},
		                        {.fd = w->fd, .events = POLLIN}};
		if (poll(pfd, 2, next_timeout(w, now)) < 0) {
			if (errno == EINTR)
				continue;
			perror("poll error");
			return 1;
		}
		if (pfd[0].revents & POLLIN) {
			struct signalfd_siginfo si;
			if (read(sfd, &si, sizeof(si)) == sizeof(si))
				printf("received %s, exiting\n", strsignal((int)si.ssi_signo));
			return 0;
		}
		if (pfd[1].revents) {
			int r = on_arp(w);
			if (r >= 0)
				return r;
		}
		int r = check_down(w);
		if (r >= 0)
			return r;
	}
}

int watch_run(const char *ifname, uint32_t ip, uint32_t gw, int always,
              const struct accept *acc) {
	struct watch w;
	memset(&w, 0, sizeof(w));
	w.ifname = ifname;
	w.ip = ip;
	w.gw = gw;
	w.acc = acc;
	conflicts_init(&w.cs, scaled_ms(DEFEND_INTERVAL_S), always);
	gateway_init(&w.g);

	if (iface_lookup(ifname, &w.ifindex, w.mine) < 0)
		return 1;
	int sfd = open_signals();
	if (sfd < 0)
		return 1;
	if (history_make_dirs() < 0 ||
	    history_open(&w.h, HISTORY_DIR, ifname) < 0) {
		close(sfd);
		return 1;
	}
	w.fd = arp_open(w.ifindex);
	if (w.fd < 0) {
		history_close(&w.h);
		close(sfd);
		return 1;
	}

	if (lockdown_enter(LOCKDOWN_WATCH) < 0) {
		close(w.fd);
		history_close(&w.h);
		close(sfd);
		return 1;
	}

	w.announce_at = now_ms();
	if (gw) {
		gateway_start(&w.g, now_ms());
		arp_request(w.fd, w.ifindex, w.mine, ip, gw);
	}

	int ret = loop(&w, sfd);
	close(w.fd);
	history_close(&w.h);
	close(sfd);
	return ret;
}
