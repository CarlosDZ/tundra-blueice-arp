#ifndef TUNDRA_EMIT_H
#define TUNDRA_EMIT_H

#include "alert.h"

void emit_alert(const struct alert *a, enum action act, const char *ifname);

#endif
