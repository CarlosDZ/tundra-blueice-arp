#include "decide.h"
#include "mac.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

int decide_probe_conflict(const struct arp_msg *m, uint32_t ip,
                          const unsigned char mine[ETH_ALEN]) {
	if (memcmp(m->sha, mine, ETH_ALEN) == 0)
		return 0;
	return m->spa == ip || (m->spa == 0 && m->tpa == ip);
}

const struct alert_def *decide_alert(const char *kase, const struct accept *acc,
                                     enum action *act) {
	const struct alert_def *def = alert_def(kase);
	if (!def)
		return NULL;
	*act = def->action;
	if (def->action == ACT_STOP && accept_covers(acc, kase, def->level))
		*act = ACT_WARN;
	return def;
}

static void add_claim(char *list, size_t size, size_t *len, uint32_t addr,
                      const unsigned char mac[ETH_ALEN]) {
	char a[INET_ADDRSTRLEN], m[18];
	inet_ntop(AF_INET, &addr, a, sizeof(a));
	int n = snprintf(list + *len, size - *len, "%s%s@%s", *len ? "," : "", a,
	                 mac_format(mac, m));
	if (n > 0 && (size_t)n < size - *len)
		*len += (size_t)n;
}

void decide_claims(struct alert *a, const struct conflicts *cs) {
	char list[ALERT_INFO_MAX] = "";
	size_t len = 0;
	for (int i = 0; i < cs->n; i++)
		add_claim(list, sizeof(list), &len, cs->recs[i].addr, cs->recs[i].mac);
	if (len)
		alert_add(a, "claim", list);
	alert_add(a, "forged", conflicts_forged(cs) ? "1" : "0");
}

void decide_addr_info(struct alert *a, enum alert_kind kind,
                      const struct conflicts *cs, uint32_t ip,
                      const struct arp_msg *m) {
	char addr[INET_ADDRSTRLEN], list[64] = "", src[18];
	size_t len = 0;

	inet_ntop(AF_INET, &ip, addr, sizeof(addr));
	if (kind != ALERT_INVALID_MAC) {
		if (kind == ALERT_CLAIMED)
			alert_add(a, "ip", addr);
		decide_claims(a, cs);
		return;
	}
	add_claim(list, sizeof(list), &len, ip, m->sha);
	alert_add(a, "ip", addr);
	alert_add(a, "claim", list);
	alert_add(a, "src", mac_format(m->src, src));
	alert_add(a, "forged", mac_frame_forged(m->sha, m->src) ? "1" : "0");
}

enum target decide_watch_target(const struct arp_msg *m, uint32_t ip,
                                uint32_t gw,
                                const unsigned char mine[ETH_ALEN]) {
	if (memcmp(m->sha, mine, ETH_ALEN) == 0)
		return T_NONE;
	if (m->spa == ip)
		return T_ADDR;
	if (gw && m->spa == gw)
		return T_GW;
	if (mac_frame_invalid(m->sha, m->src))
		return T_NET;
	return T_NONE;
}

int decide_warn_once(struct warned *w, const char *kase,
                     const unsigned char mac[ETH_ALEN]) {
	for (int i = 0; i < w->n; i++)
		if (strcmp(w->kase[i], kase) == 0 &&
		    memcmp(w->mac[i], mac, ETH_ALEN) == 0)
			return 0;
	if (w->n < WARNED_MAX) {
		snprintf(w->kase[w->n], sizeof(w->kase[w->n]), "%s", kase);
		memcpy(w->mac[w->n], mac, ETH_ALEN);
		w->n++;
	}
	return 1;
}

void decide_gw_info(struct alert *a, const struct gateway *g, uint32_t gw,
                    const struct arp_msg *invalid) {
	char addr[INET_ADDRSTRLEN], m[18], list[GW_MAX_MACS * 18] = "";
	size_t len = 0;

	inet_ntop(AF_INET, &gw, addr, sizeof(addr));
	alert_add(a, "gw", addr);
	if (g->known)
		alert_add(a, "known", mac_format(g->mac, m));
	if (invalid) {
		alert_add(a, "seen", mac_format(invalid->sha, m));
		alert_add(a, "src", mac_format(invalid->src, m));
		alert_add(a, "forged",
		          mac_frame_forged(invalid->sha, invalid->src) ? "1" : "0");
		return;
	}
	for (int i = 0; i < g->nseen; i++) {
		int n = snprintf(list + len, sizeof(list) - len, "%s%s", len ? "," : "",
		                 mac_format(g->seen[i], m));
		if (n > 0 && (size_t)n < sizeof(list) - len)
			len += (size_t)n;
	}
	if (len)
		alert_add(a, "seen", list);
	alert_add(a, "forged", g->forged ? "1" : "0");
}

void decide_net_info(struct alert *a, const struct arp_msg *m) {
	char addr[INET_ADDRSTRLEN], mac[18];
	inet_ntop(AF_INET, &m->spa, addr, sizeof(addr));
	alert_add(a, "ip", addr);
	alert_add(a, "sha", mac_format(m->sha, mac));
	alert_add(a, "src", mac_format(m->src, mac));
	alert_add(a, "forged", mac_frame_forged(m->sha, m->src) ? "1" : "0");
}
