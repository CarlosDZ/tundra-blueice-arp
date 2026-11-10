#ifndef TUNDRA_LOCKDOWN_H
#define TUNDRA_LOCKDOWN_H

enum lockdown_mode { LOCKDOWN_PROBE, LOCKDOWN_WATCH };

int lockdown_enter(enum lockdown_mode mode);

#endif
