#include "alert.h"

#include <stdio.h>
#include <string.h>

static const struct alert_def defs[] = {
    {"D", ACT_STOP, 8, "gateway impersonation"},
    {"mac-gw", ACT_STOP, 8, "crafted MAC answering for the gateway"},
    {"mac-addr", ACT_STOP, 7, "crafted MAC claiming the address"},
    {"C", ACT_STOP, 6, "address in use repeatedly claimed"},
    {"A", ACT_STOP, 4, "single host claiming addresses"},
    {"B", ACT_STOP, 4, "many hosts claiming addresses"},
    {"mac-net", ACT_WARN, 2, "crafted ARP on the network"},
};

const struct alert_def *alert_def(const char *kase) {
	for (size_t i = 0; i < sizeof(defs) / sizeof(defs[0]); i++)
		if (strcmp(defs[i].kase, kase) == 0)
			return &defs[i];
	return NULL;
}

static int safe(unsigned char ch) {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
	       (ch >= '0' && ch <= '9') || (ch && strchr("._:@,/-", ch));
}

int alert_encode(char *out, size_t size, const char *in) {
	static const char hex[] = "0123456789ABCDEF";
	size_t n = 0;

	if (!in[0])
		return -1;
	for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
		if (safe(*p)) {
			if (n + 1 >= size)
				return -1;
			out[n++] = (char)*p;
		} else {
			if (n + 3 >= size)
				return -1;
			out[n++] = '%';
			out[n++] = hex[*p >> 4];
			out[n++] = hex[*p & 15];
		}
	}
	out[n] = '\0';
	return 0;
}

int alert_init(struct alert *a, const char *kase) {
	memset(a, 0, sizeof(*a));
	a->def = alert_def(kase);
	if (!a->def)
		return -1;
	a->len = (size_t)snprintf(a->info, sizeof(a->info), "case %s", kase);
	return 0;
}

void alert_add(struct alert *a, const char *key, const char *value) {
	char enc[ALERT_INFO_MAX];
	if (a->bad || alert_encode(enc, sizeof(enc), value) < 0) {
		a->bad = 1;
		return;
	}
	int n = snprintf(a->info + a->len, sizeof(a->info) - a->len, " %s %s", key,
	                 enc);
	if (n < 0 || (size_t)n >= sizeof(a->info) - a->len) {
		a->bad = 1;
		return;
	}
	a->len += (size_t)n;
}

static const char *action_name(enum action action) {
	switch (action) {
	case ACT_STOP:
		return "stop";
	case ACT_WARN:
		return "warn";
	case ACT_REINFORCE:
		return "reinforce";
	}
	return "warn";
}

int alert_format(char *buf, size_t size, const struct alert *a,
                 enum action action, const char *ifname, uint64_t ts_ms) {
	char on[64];
	if (!a->def || a->bad || alert_encode(on, sizeof(on), ifname) < 0)
		return -1;

	int n = snprintf(
	    buf, size,
	    "alert %d/%d %s by tundra-blueice-arp on %s ts %llu.%03llu "
	    "reply %s info %s -- %s",
	    ALERT_CODE, a->def->level, action_name(action), on,
	    (unsigned long long)(ts_ms / 1000), (unsigned long long)(ts_ms % 1000),
	    action == ACT_STOP ? "force,disconnect" : "ack,disconnect", a->info,
	    a->def->text);
	if (n < 0 || (size_t)n >= size)
		return -1;
	return 0;
}
