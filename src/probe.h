#ifndef TUNDRA_PROBE_H
#define TUNDRA_PROBE_H

#include "accept.h"

#include <stdint.h>

int probe_run(const char *ifname, uint32_t ip, const struct accept *acc);

#endif
