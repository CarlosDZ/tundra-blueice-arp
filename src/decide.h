#ifndef TUNDRA_DECIDE_H
#define TUNDRA_DECIDE_H

#include "accept.h"
#include "alert.h"
#include "arp.h"
#include "conflict.h"
#include "gateway.h"

#include <stdint.h>

#define WARNED_MAX 16

enum target { T_NONE, T_ADDR, T_GW, T_NET };

struct warned {
	char kase[WARNED_MAX][16];
	unsigned char mac[WARNED_MAX][ETH_ALEN];
	int n;
};

int decide_probe_conflict(const struct arp_msg *m, uint32_t ip,
                          const unsigned char mine[ETH_ALEN]);
const struct alert_def *decide_alert(const char *kase, const struct accept *acc,
                                     enum action *act);
void decide_claims(struct alert *a, const struct conflicts *cs);
void decide_addr_info(struct alert *a, enum alert_kind kind,
                      const struct conflicts *cs, uint32_t ip,
                      const struct arp_msg *m);
enum target decide_watch_target(const struct arp_msg *m, uint32_t ip,
                                uint32_t gw,
                                const unsigned char mine[ETH_ALEN]);
int decide_warn_once(struct warned *w, const char *kase,
                     const unsigned char mac[ETH_ALEN]);
void decide_gw_info(struct alert *a, const struct gateway *g, uint32_t gw,
                    const struct arp_msg *invalid);
void decide_net_info(struct alert *a, const struct arp_msg *m);

#endif
