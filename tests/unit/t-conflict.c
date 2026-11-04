#include "guard/conflict.c"
#include "guard/mac.c"
#include "test.h"

#define DEFEND_MS 10000
#define S 1000

static const unsigned char evil[ETH_ALEN] = {2, 0xaa, 0xaa, 0xaa, 0xaa, 1};
static const unsigned char other[ETH_ALEN] = {2, 0xbb, 0xbb, 0xbb, 0xbb, 1};
static const unsigned char multicast[ETH_ALEN] = {1, 0, 0x5e, 0, 0, 1};
static const unsigned char zero[ETH_ALEN] = {0};

static uint32_t ip(int n) { return (uint32_t)(0x0a000000 | n); }

static void test_probe(void) {
	struct conflicts cs;
	enum alert_kind k;
	conflicts_init(&cs, DEFEND_MS, 0);

	CHECK(conflict_probe(&cs, ip(1), evil, evil, 1 * S, &k) == V_GIVE_UP &&
	          k == ALERT_NONE,
	      "a probe conflict gives the address up");
	CHECK(conflict_probe(&cs, ip(2), evil, evil, 2 * S, &k) == V_GIVE_UP &&
	          k == ALERT_NONE,
	      "a second address taken by the same host is no alert yet");
	CHECK(conflict_probe(&cs, ip(3), evil, evil, 3 * S, &k) == V_GIVE_UP &&
	          k == ALERT_SAME_HOST,
	      "A: a third address taken by the same host");

	conflicts_init(&cs, DEFEND_MS, 0);
	conflict_probe(&cs, ip(1), evil, evil, 0, &k);
	conflict_probe(&cs, ip(1), evil, evil, S, &k);
	conflict_probe(&cs, ip(1), evil, evil, 2 * S, &k);
	CHECK(k == ALERT_NONE, "the same address repeated by one host is not A");

	conflicts_init(&cs, DEFEND_MS, 0);
	conflict_probe(&cs, ip(1), multicast, multicast, 0, &k);
	CHECK(k == ALERT_INVALID_MAC, "a multicast responder is mac-addr at once");
	conflicts_init(&cs, DEFEND_MS, 0);
	conflict_probe(&cs, ip(1), zero, zero, 0, &k);
	CHECK(k == ALERT_INVALID_MAC, "an all-zero responder is mac-addr at once");
	conflicts_init(&cs, DEFEND_MS, 0);
	conflict_probe(&cs, ip(1), evil, multicast, 0, &k);
	CHECK(k == ALERT_INVALID_MAC,
	      "an invalid Ethernet source is mac-addr at once");
}

static void test_many_hosts(void) {
	struct conflicts cs;
	enum alert_kind k = ALERT_NONE;
	int before = 1;
	conflicts_init(&cs, DEFEND_MS, 0);

	for (int i = 0; i < 10; i++) {
		unsigned char mac[ETH_ALEN] = {2, 0, 0, 0, 0, (unsigned char)i};
		conflict_probe(&cs, ip(i), mac, mac, (uint64_t)i * S, &k);
		if (i < 9 && k != ALERT_NONE)
			before = 0;
	}
	CHECK(before, "B: fewer than ten hosts raise nothing");
	CHECK(k == ALERT_MANY_HOSTS, "B: the tenth distinct host");
}

static void test_window(void) {
	struct conflicts cs;
	enum alert_kind k;
	conflicts_init(&cs, DEFEND_MS, 0);

	conflict_probe(&cs, ip(1), evil, evil, 0, &k);
	conflict_probe(&cs, ip(2), evil, evil, S, &k);
	conflict_probe(&cs, ip(3), evil, evil, CONFLICT_WINDOW_MS + 2 * S, &k);
	CHECK(k == ALERT_NONE, "conflicts older than the window are forgotten");

	conflicts_init(&cs, DEFEND_MS, 0);
	for (int i = 0; i < 20; i++) {
		unsigned char mac[ETH_ALEN] = {2, 1, 0, 0, 0, (unsigned char)i};
		conflict_probe(&cs, ip(100 + i), mac, mac, (uint64_t)i, &k);
	}
	CHECK(cs.n == CONFLICT_MAX, "the record keeps a bounded history");
}

static void test_claims(void) {
	struct conflicts cs;
	enum alert_kind k;
	conflicts_init(&cs, DEFEND_MS, 0);

	CHECK(conflict_claim(&cs, ip(1), evil, evil, 100 * S, &k) == V_DEFEND &&
	          k == ALERT_NONE,
	      "the first claim is defended");
	CHECK(conflict_claim(&cs, ip(1), evil, evil, 105 * S, &k) == V_GIVE_UP,
	      "once: a claim within the defense interval gives up");

	conflicts_init(&cs, DEFEND_MS, 0);
	CHECK(conflict_claim(&cs, ip(1), evil, evil, 100 * S, &k) == V_DEFEND &&
	          conflict_claim(&cs, ip(1), other, other, 111 * S, &k) == V_DEFEND,
	      "spaced claims are defended");
	CHECK(conflict_claim(&cs, ip(1), evil, evil, 122 * S, &k) == V_DEFEND &&
	          k == ALERT_CLAIMED,
	      "C: the third claim on the address in use");

	conflicts_init(&cs, DEFEND_MS, 0);
	conflict_claim(&cs, ip(1), multicast, multicast, 0, &k);
	CHECK(k == ALERT_INVALID_MAC, "an invalid MAC claiming the address");

	conflicts_init(&cs, DEFEND_MS, 0);
	conflict_claim(&cs, ip(1), evil, evil, 100 * S, &k);
	conflicts_new_address(&cs);
	CHECK(conflict_claim(&cs, ip(2), other, other, 101 * S, &k) == V_DEFEND,
	      "a new address starts a fresh defense interval");
}

static void test_always(void) {
	struct conflicts cs;
	enum alert_kind k;
	int never = 1;
	conflicts_init(&cs, DEFEND_MS, 1);

	CHECK(conflict_claim(&cs, ip(1), evil, evil, 100 * S, &k) == V_DEFEND,
	      "always: the first claim is defended");
	CHECK(conflict_claim(&cs, ip(1), evil, evil, 101 * S, &k) == V_HOLD,
	      "always: a claim within the interval is held");
	for (int i = 0; i < 10; i++) {
		const unsigned char *m = i % 2 ? multicast : other;
		if (conflict_claim(&cs, ip(1), m, m, (uint64_t)(102 + i * 11) * S,
		                   &k) == V_GIVE_UP)
			never = 0;
	}
	CHECK(never, "always: never gives up");

	conflicts_init(&cs, DEFEND_MS, 1);
	conflict_claim(&cs, ip(1), multicast, multicast, 0, &k);
	CHECK(k == ALERT_INVALID_MAC, "always: an invalid MAC is still mac-addr");

	conflicts_init(&cs, DEFEND_MS, 1);
	conflict_claim(&cs, ip(1), evil, evil, 0, &k);
	conflict_claim(&cs, ip(1), evil, evil, 11 * S, &k);
	conflict_claim(&cs, ip(1), evil, evil, 22 * S, &k);
	CHECK(k == ALERT_CLAIMED, "always: repeated claims are still C");
}

static void test_hints(void) {
	struct conflicts cs;
	enum alert_kind k;
	conflicts_init(&cs, DEFEND_MS, 0);

	conflict_probe(&cs, ip(1), evil, evil, 0, &k);
	CHECK(!conflicts_forged(&cs), "genuine replies are not forged");
	conflict_probe(&cs, ip(2), other, evil, S, &k);
	CHECK(conflicts_forged(&cs), "a reply whose sender differs is forged");
	CHECK(conflicts_has_mac(&cs, other) && !conflicts_has_mac(&cs, zero),
	      "responder MACs can be looked up");
}

static void test_case(void) {
	CHECK(strcmp(alert_case(ALERT_SAME_HOST), "A") == 0 &&
	          strcmp(alert_case(ALERT_MANY_HOSTS), "B") == 0 &&
	          strcmp(alert_case(ALERT_CLAIMED), "C") == 0 &&
	          strcmp(alert_case(ALERT_INVALID_MAC), "mac-addr") == 0 &&
	          alert_case(ALERT_NONE) == NULL,
	      "case tokens");
}

int main(void) {
	test_probe();
	test_many_hosts();
	test_window();
	test_claims();
	test_always();
	test_hints();
	test_case();
	return test_summary();
}
