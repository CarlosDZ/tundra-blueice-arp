#ifndef TUNDRA_HISTORY_H
#define TUNDRA_HISTORY_H

#include "conflict.h"

#include <stdint.h>

#define HISTORY_DIR "/run/tundra/blueice/arp"

struct history {
	char path[256];
	char lock[256];
	int lockfd;
};

int history_make_dirs(void);
int history_open(struct history *h, const char *dir, const char *ifname);
void history_close(struct history *h);
int history_begin(struct history *h, struct conflicts *cs, uint64_t now);
int history_commit(struct history *h, const struct conflicts *cs);
int history_load(const char *path, struct conflicts *cs, uint64_t now);
int history_save(const char *path, const struct conflicts *cs);

#endif
