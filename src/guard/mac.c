#include "mac.h"

#include <string.h>

int mac_invalid(const unsigned char m[ETH_ALEN]) {
	static const unsigned char zero[ETH_ALEN];
	return (m[0] & 1) || memcmp(m, zero, ETH_ALEN) == 0;
}

int mac_frame_invalid(const unsigned char sha[ETH_ALEN],
                      const unsigned char src[ETH_ALEN]) {
	return mac_invalid(sha) || mac_invalid(src);
}

int mac_frame_forged(const unsigned char sha[ETH_ALEN],
                     const unsigned char src[ETH_ALEN]) {
	return memcmp(sha, src, ETH_ALEN) != 0;
}
