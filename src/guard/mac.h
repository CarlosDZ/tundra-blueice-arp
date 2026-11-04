#ifndef TUNDRA_MAC_H
#define TUNDRA_MAC_H

#include <linux/if_ether.h>

int mac_invalid(const unsigned char m[ETH_ALEN]);
int mac_frame_invalid(const unsigned char sha[ETH_ALEN],
                      const unsigned char src[ETH_ALEN]);
int mac_frame_forged(const unsigned char sha[ETH_ALEN],
                     const unsigned char src[ETH_ALEN]);
const char *mac_format(const unsigned char m[ETH_ALEN], char buf[18]);

#endif
