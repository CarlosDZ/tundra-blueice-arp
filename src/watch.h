#ifndef TUNDRA_WATCH_H
#define TUNDRA_WATCH_H

#include "accept.h"

#include <stdint.h>

int watch_run(const char *ifname, uint32_t ip, uint32_t gw, int always,
              const struct accept *acc);

#endif
