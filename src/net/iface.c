#include "iface.h"

#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int iface_lookup(const char *ifname, int *ifindex,
                 unsigned char mac[ETH_ALEN]) {
	unsigned int idx = if_nametoindex(ifname);
	if (!idx) {
		fprintf(stderr, "%s: %s\n", ifname, strerror(errno));
		return -1;
	}

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket error");
		return -1;
	}
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	int r = ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	if (r < 0) {
		perror("SIOCGIFHWADDR error");
		return -1;
	}

	*ifindex = (int)idx;
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}
