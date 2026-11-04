#include "conflict.h"
#include "mac.h"

#include <string.h>

void conflicts_init(struct conflicts *cs, uint64_t defend_ms, int always) {
	memset(cs, 0, sizeof(*cs));
	cs->defend_ms = defend_ms;
	cs->always = always;
}

void conflicts_new_address(struct conflicts *cs) { cs->last_defense = 0; }

static void record(struct conflicts *cs, uint32_t addr,
                   const unsigned char mac[ETH_ALEN], int bound, int forged,
                   uint64_t now) {
	int n = 0;
	for (int i = 0; i < cs->n; i++)
		if (now - cs->recs[i].at < CONFLICT_WINDOW_MS)
			cs->recs[n++] = cs->recs[i];
	if (n == CONFLICT_MAX) {
		memmove(&cs->recs[0], &cs->recs[1],
		        (CONFLICT_MAX - 1) * sizeof(cs->recs[0]));
		n--;
	}
	cs->recs[n].at = now;
	cs->recs[n].addr = addr;
	memcpy(cs->recs[n].mac, mac, ETH_ALEN);
	cs->recs[n].bound = bound;
	cs->recs[n].forged = forged;
	cs->n = n + 1;
}

static int pair_seen(const struct conflicts *cs, int i) {
	for (int j = 0; j < i; j++)
		if (cs->recs[j].addr == cs->recs[i].addr &&
		    memcmp(cs->recs[j].mac, cs->recs[i].mac, ETH_ALEN) == 0)
			return 1;
	return 0;
}

static enum alert_kind evaluate(const struct conflicts *cs, int invalid,
                                const unsigned char mac[ETH_ALEN]) {
	if (invalid)
		return ALERT_INVALID_MAC;

	int addrs = 0, pairs = 0, claims = 0;
	for (int i = 0; i < cs->n; i++) {
		if (cs->recs[i].bound)
			claims++;
		if (pair_seen(cs, i))
			continue;
		pairs++;
		if (memcmp(cs->recs[i].mac, mac, ETH_ALEN) == 0)
			addrs++;
	}
	if (addrs >= LIMIT_SAME_MAC)
		return ALERT_SAME_HOST;
	if (claims >= LIMIT_CLAIMS)
		return ALERT_CLAIMED;
	if (pairs >= LIMIT_PAIRS)
		return ALERT_MANY_HOSTS;
	return ALERT_NONE;
}

enum verdict conflict_probe(struct conflicts *cs, uint32_t addr,
                            const unsigned char sha[ETH_ALEN],
                            const unsigned char src[ETH_ALEN], uint64_t now,
                            enum alert_kind *kind) {
	record(cs, addr, sha, 0, mac_frame_forged(sha, src), now);
	*kind = evaluate(cs, mac_frame_invalid(sha, src), sha);
	return V_GIVE_UP;
}

enum verdict conflict_claim(struct conflicts *cs, uint32_t addr,
                            const unsigned char sha[ETH_ALEN],
                            const unsigned char src[ETH_ALEN], uint64_t now,
                            enum alert_kind *kind) {
	int recent = cs->last_defense && now - cs->last_defense < cs->defend_ms;

	record(cs, addr, sha, 1, mac_frame_forged(sha, src), now);
	*kind = evaluate(cs, mac_frame_invalid(sha, src), sha);
	if (recent)
		return cs->always ? V_HOLD : V_GIVE_UP;
	cs->last_defense = now;
	return V_DEFEND;
}

int conflicts_forged(const struct conflicts *cs) {
	for (int i = 0; i < cs->n; i++)
		if (cs->recs[i].forged)
			return 1;
	return 0;
}

int conflicts_has_mac(const struct conflicts *cs,
                      const unsigned char mac[ETH_ALEN]) {
	for (int i = 0; i < cs->n; i++)
		if (memcmp(cs->recs[i].mac, mac, ETH_ALEN) == 0)
			return 1;
	return 0;
}

const char *alert_case(enum alert_kind kind) {
	switch (kind) {
	case ALERT_INVALID_MAC:
		return "mac-addr";
	case ALERT_SAME_HOST:
		return "A";
	case ALERT_MANY_HOSTS:
		return "B";
	case ALERT_CLAIMED:
		return "C";
	case ALERT_NONE:
		break;
	}
	return NULL;
}
