#include "alert.h"

#include <string.h>

#define ALERT_BY "tundra-blueice-arp"

static const struct alert_def defs[] = {
    {"D", BLUEICE_STOP, 8, "gateway impersonation"},
    {"mac-gw", BLUEICE_STOP, 8, "crafted MAC answering for the gateway"},
    {"mac-addr", BLUEICE_STOP, 7, "crafted MAC claiming the address"},
    {"C", BLUEICE_STOP, 6, "address in use repeatedly claimed"},
    {"A", BLUEICE_STOP, 4, "single host claiming addresses"},
    {"B", BLUEICE_STOP, 4, "many hosts claiming addresses"},
    {"mac-net", BLUEICE_WARN, 2, "crafted ARP on the network"},
};

const struct alert_def *alert_def(const char *kase) {
	for (size_t i = 0; i < sizeof(defs) / sizeof(defs[0]); i++)
		if (strcmp(defs[i].kase, kase) == 0)
			return &defs[i];
	return NULL;
}

int alert_init(struct alert *a, const char *kase) {
	memset(a, 0, sizeof(*a));
	a->def = alert_def(kase);
	if (!a->def)
		return -1;
	return blueice_alert_init(&a->line, ALERT_BY, kase, a->def->level,
	                          a->def->text);
}

void alert_add(struct alert *a, const char *key, const char *value) {
	if (a->def)
		blueice_alert_add(&a->line, key, value);
}

int alert_format(char *buf, size_t size, const struct alert *a,
                 enum blueice_action action, const char *ifname,
                 uint64_t ts_ms) {
	if (!a->def)
		return -1;
	return blueice_alert_format(buf, size, &a->line, action, ifname, ts_ms);
}
