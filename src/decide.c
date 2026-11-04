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

void decide_probe_info(struct alert *a, enum alert_kind kind,
                       const struct conflicts *cs, uint32_t ip,
                       const struct arp_msg *m) {
	char addr[INET_ADDRSTRLEN], list[64] = "", src[18];
	size_t len = 0;

	if (kind != ALERT_INVALID_MAC) {
		decide_claims(a, cs);
		return;
	}
	inet_ntop(AF_INET, &ip, addr, sizeof(addr));
	add_claim(list, sizeof(list), &len, ip, m->sha);
	alert_add(a, "ip", addr);
	alert_add(a, "claim", list);
	alert_add(a, "src", mac_format(m->src, src));
	alert_add(a, "forged", mac_frame_forged(m->sha, m->src) ? "1" : "0");
}
