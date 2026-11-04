#include "accept.h"
#include "alert.h"

#include <stdio.h>
#include <string.h>

static const struct accept_item *find(const struct accept *a,
                                      const char *kase) {
	for (int i = 0; i < a->n; i++)
		if (strcmp(a->items[i].kase, kase) == 0)
			return &a->items[i];
	return NULL;
}

static int parse_level(const char *s) {
	if (s[0] < '1' || s[0] > '9')
		return -1;
	if (s[1] == '\0')
		return s[0] - '0';
	if (strcmp(s, "10") == 0)
		return 10;
	return -1;
}

int accept_parse(struct accept *a, const char *s) {
	char buf[128];
	memset(a, 0, sizeof(*a));
	int len = snprintf(buf, sizeof(buf), "%s", s);
	if (len < 0 || (size_t)len >= sizeof(buf))
		return -1;

	for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
		char *slash = strchr(tok, '/');
		if (!slash || a->n == ACCEPT_MAX)
			return -1;
		*slash++ = '\0';
		int level = parse_level(slash);
		if (level < 0 || !alert_def(tok) || find(a, tok))
			return -1;
		snprintf(a->items[a->n].kase, sizeof(a->items[a->n].kase), "%s", tok);
		a->items[a->n].level = level;
		a->n++;
	}
	return a->n ? 0 : -1;
}

int accept_covers(const struct accept *a, const char *kase, int level) {
	const struct accept_item *it = find(a, kase);
	return it && level <= it->level;
}
