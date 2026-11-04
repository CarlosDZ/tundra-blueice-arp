#include "guard/mac.c"
#include "test.h"

static const unsigned char host[ETH_ALEN] = {2, 0xaa, 0xaa, 0xaa, 0xaa, 1};
static const unsigned char other[ETH_ALEN] = {2, 0xbb, 0xbb, 0xbb, 0xbb, 1};
static const unsigned char multicast[ETH_ALEN] = {1, 0, 0x5e, 0, 0, 1};
static const unsigned char broadcast[ETH_ALEN] = {0xff, 0xff, 0xff,
                                                  0xff, 0xff, 0xff};
static const unsigned char zero[ETH_ALEN] = {0};

int main(void) {
	CHECK(!mac_invalid(host), "a unicast MAC is valid");
	CHECK(mac_invalid(multicast), "a multicast MAC is invalid");
	CHECK(mac_invalid(broadcast), "the broadcast MAC is invalid");
	CHECK(mac_invalid(zero), "the all-zero MAC is invalid");

	CHECK(!mac_frame_invalid(host, host), "a genuine frame is valid");
	CHECK(mac_frame_invalid(multicast, host),
	      "an invalid ARP sender is caught");
	CHECK(mac_frame_invalid(host, multicast),
	      "an invalid Ethernet source is caught");

	CHECK(!mac_frame_forged(host, host), "matching MACs are not forged");
	CHECK(mac_frame_forged(host, other),
	      "an ARP sender different from the frame source is forged");
	char buf[18];
	CHECK(strcmp(mac_format(host, buf), "02:aa:aa:aa:aa:01") == 0,
	      "formats a MAC in lowercase hex");
	return test_summary();
}
