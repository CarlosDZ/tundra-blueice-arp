#include "emit.h"
#include "timing.h"

#include <stdio.h>

void emit_alert(const struct alert *a, enum blueice_action act,
                const char *ifname) {
	char line[1024];
	if (alert_format(line, sizeof(line), a, act, ifname, wall_ms()) == 0)
		fprintf(stderr, "%s\n", line);
	else
		fprintf(stderr, "could not format the %s alert on %s\n",
		        a->def ? a->def->kase : "unknown", ifname);
}
