#include "accept.h"
#include "parent.h"
#include "probe.h"
#include "watch.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

struct opts {
	struct accept acc;
	uint32_t addr;
	uint32_t gw;
	int always;
};

static void usage(void) {
	fprintf(stderr, "usage: tundra-blueice-arp probe <interface> <address> "
	                "[accept <case>/<level>,...]\n"
	                "       tundra-blueice-arp watch <interface> addr "
	                "<address> [gw <address>] [defend once|always] "
	                "[accept <case>/<level>,...]\n");
}

static int repeated(char *argv[], int first, int i) {
	for (int j = first; j < i; j += 2)
		if (strcmp(argv[j], argv[i]) == 0)
			return 1;
	return 0;
}

static int parse_ip(const char *what, const char *s, uint32_t *out) {
	struct in_addr a;
	if (inet_pton(AF_INET, s, &a) != 1 || a.s_addr == 0) {
		fprintf(stderr, "invalid %s: %s\n", what, s);
		return -1;
	}
	*out = a.s_addr;
	return 0;
}

static int parse_option(int watch, const char *key, const char *val,
                        struct opts *o) {
	if (strcmp(key, "accept") == 0) {
		if (accept_parse(&o->acc, val) == 0)
			return 0;
		fprintf(stderr, "invalid accept: %s\n", val);
		return -1;
	}
	if (watch && strcmp(key, "addr") == 0)
		return parse_ip("address", val, &o->addr);
	if (watch && strcmp(key, "gw") == 0)
		return parse_ip("gateway", val, &o->gw);
	if (watch && strcmp(key, "defend") == 0) {
		if (strcmp(val, "once") == 0 || strcmp(val, "always") == 0) {
			o->always = strcmp(val, "always") == 0;
			return 0;
		}
		fprintf(stderr, "invalid defend: %s\n", val);
		return -1;
	}
	usage();
	return -1;
}

static int parse_options(int argc, char *argv[], int first, int watch,
                         struct opts *o) {
	if ((argc - first) % 2 != 0) {
		usage();
		return -1;
	}
	for (int i = first; i < argc; i += 2) {
		if (repeated(argv, first, i)) {
			fprintf(stderr, "repeated option: %s\n", argv[i]);
			return -1;
		}
		if (parse_option(watch, argv[i], argv[i + 1], o) < 0)
			return -1;
	}
	return 0;
}

static int parse_ifname(const char *s) {
	if (s[0] == '\0' || strlen(s) >= IFNAMSIZ || strchr(s, '/')) {
		fprintf(stderr, "invalid interface: %s\n", s);
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[]) {
	parent_bind();

	if (argc == 2 && strcmp(argv[1], "--version") == 0) {
		printf("tundra-blueice-arp %s\n", TUNDRA_BLUEICE_ARP_VERSION);
		return 0;
	}
	if (argc < 4) {
		usage();
		return 2;
	}

	struct opts o;
	memset(&o, 0, sizeof(o));
	/* Nothing in stdio may allocate, dup or query the terminal after the
	 * lockdown: stdout gets its buffer now and stderr its orientation
	 * (glibc's perror dups an unoriented stderr). */
	static char outbuf[BUFSIZ];
	setvbuf(stdout, outbuf, _IOLBF, sizeof(outbuf));
	fwide(stderr, -1);

	if (strcmp(argv[1], "probe") == 0) {
		if (parse_ifname(argv[2]) < 0 ||
		    parse_ip("address", argv[3], &o.addr) < 0 ||
		    parse_options(argc, argv, 4, 0, &o) < 0)
			return 2;
		return probe_run(argv[2], o.addr, &o.acc);
	}
	if (strcmp(argv[1], "watch") == 0) {
		if (parse_ifname(argv[2]) < 0 ||
		    parse_options(argc, argv, 3, 1, &o) < 0)
			return 2;
		if (!o.addr) {
			fprintf(stderr, "watch requires addr\n");
			return 2;
		}
		signal(SIGHUP, SIG_IGN);
		signal(SIGPIPE, SIG_IGN);
		return watch_run(argv[2], o.addr, o.gw, o.always, &o.acc);
	}
	usage();
	return 2;
}
