#ifndef TUNDRA_ALERT_H
#define TUNDRA_ALERT_H

#include <stddef.h>
#include <stdint.h>

#define ALERT_CODE 111
#define ALERT_INFO_MAX 768

enum action { ACT_STOP, ACT_WARN, ACT_REINFORCE };

struct alert_def {
	const char *kase;
	enum action action;
	int level;
	const char *text;
};

struct alert {
	const struct alert_def *def;
	char info[ALERT_INFO_MAX];
	size_t len;
	int bad;
};

const struct alert_def *alert_def(const char *kase);
int alert_encode(char *out, size_t size, const char *in);
int alert_init(struct alert *a, const char *kase);
void alert_add(struct alert *a, const char *key, const char *value);
int alert_format(char *buf, size_t size, const struct alert *a,
                 enum action action, const char *ifname, uint64_t ts_ms);

#endif
