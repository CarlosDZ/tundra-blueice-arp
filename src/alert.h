#ifndef TUNDRA_ALERT_H
#define TUNDRA_ALERT_H

#include <tundra/blueice.h>

struct alert_def {
	const char *kase;
	enum blueice_action action;
	int level;
	const char *text;
};

struct alert {
	const struct alert_def *def;
	struct blueice_alert line;
};

const struct alert_def *alert_def(const char *kase);
int alert_init(struct alert *a, const char *kase);
void alert_add(struct alert *a, const char *key, const char *value);
int alert_format(char *buf, size_t size, const struct alert *a,
                 enum blueice_action action, const char *ifname,
                 uint64_t ts_ms);

#endif
