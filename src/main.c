#include "accept.h"
#include "probe.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>

static void usage(void) {
	fprintf(stderr, "usage: tundra-blueice-arp probe <interface> <address> "
	                "[accept <case>/<level>,...]\n");
}

static int repeated(char *argv[], int first, int i) {
	for (int j = first; j < i; j += 2)
		if (strcmp(argv[j], argv[i]) == 0)
			return 1;
	return 0;
}

static int parse_options(int argc, char *argv[], int first,
                         struct accept *acc) {
	if ((argc - first) % 2 != 0) {
		usage();
		return -1;
	}
	for (int i = first; i < argc; i += 2) {
		if (repeated(argv, first, i)) {
			fprintf(stderr, "repeated option: %s\n", argv[i]);
			return -1;
		}
		if (strcmp(argv[i], "accept") == 0) {
			if (accept_parse(acc, argv[i + 1]) < 0) {
				fprintf(stderr, "invalid accept: %s\n", argv[i + 1]);
				return -1;
			}
		} else {
			usage();
			return -1;
		}
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

static int parse_ip(const char *s, uint32_t *out) {
	struct in_addr a;
	if (inet_pton(AF_INET, s, &a) != 1 || a.s_addr == 0) {
		fprintf(stderr, "invalid address: %s\n", s);
		return -1;
	}
	*out = a.s_addr;
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc == 2 && strcmp(argv[1], "--version") == 0) {
		printf("tundra-blueice-arp %s\n", TUNDRA_BLUEICE_ARP_VERSION);
		return 0;
	}
	if (argc < 4 || strcmp(argv[1], "probe") != 0) {
		usage();
		return 2;
	}

	struct accept acc = {0};
	uint32_t ip;
	if (parse_ifname(argv[2]) < 0 || parse_ip(argv[3], &ip) < 0 ||
	    parse_options(argc, argv, 4, &acc) < 0)
		return 2;

	setvbuf(stdout, NULL, _IOLBF, 0);
	return probe_run(argv[2], ip, &acc);
}
