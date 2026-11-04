#ifndef TUNDRA_ACCEPT_H
#define TUNDRA_ACCEPT_H

#define ACCEPT_MAX 8

struct accept_item {
	char kase[16];
	int level;
};

struct accept {
	struct accept_item items[ACCEPT_MAX];
	int n;
};

int accept_parse(struct accept *a, const char *s);
int accept_covers(const struct accept *a, const char *kase, int level);

#endif
