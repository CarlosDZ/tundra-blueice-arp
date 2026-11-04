#include <stdio.h>
#include <string.h>

static void usage(void) {
	fprintf(stderr, "usage: tundra-blueice-arp probe <interface> <address>\n"
	                "       tundra-blueice-arp watch <interface> addr "
	                "<address> [gw <address>]\n");
}

int main(int argc, char *argv[]) {
	if (argc == 2 && strcmp(argv[1], "--version") == 0) {
		printf("tundra-blueice-arp %s\n", TUNDRA_BLUEICE_ARP_VERSION);
		return 0;
	}
	usage();
	return 2;
}
