#ifndef TUNDRA_IFACE_H
#define TUNDRA_IFACE_H

#include <linux/if_ether.h>

int iface_lookup(const char *ifname, int *ifindex, unsigned char mac[ETH_ALEN]);

#endif
