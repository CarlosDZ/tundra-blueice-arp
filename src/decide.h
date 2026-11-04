#ifndef TUNDRA_DECIDE_H
#define TUNDRA_DECIDE_H

#include "accept.h"
#include "alert.h"
#include "arp.h"
#include "conflict.h"

#include <stdint.h>

int decide_probe_conflict(const struct arp_msg *m, uint32_t ip,
                          const unsigned char mine[ETH_ALEN]);
const struct alert_def *decide_alert(const char *kase, const struct accept *acc,
                                     enum action *act);
void decide_claims(struct alert *a, const struct conflicts *cs);
void decide_probe_info(struct alert *a, enum alert_kind kind,
                       const struct conflicts *cs, uint32_t ip,
                       const struct arp_msg *m);

#endif
