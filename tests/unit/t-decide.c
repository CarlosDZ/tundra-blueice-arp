#include "accept.c"
#include "alert.c"
#include "decide.c"
#include "guard/conflict.c"
#include "guard/mac.c"
#include "test.h"

static const unsigned char mine[ETH_ALEN] = {2, 0x11, 0x11, 0x11, 0x11, 1};
static const unsigned char evil[ETH_ALEN] = {2, 0xaa, 0xaa, 0xaa, 0xaa, 1};
static const unsigned char other[ETH_ALEN] = {2, 0xbb, 0xbb, 0xbb, 0xbb, 1};
static const unsigned char multicast[ETH_ALEN] = {1, 0, 0x5e, 0, 0, 1};

static struct arp_msg msg(const unsigned char *sha, const unsigned char *src,
                          const char *spa, const char *tpa) {
	struct arp_msg m;
	memset(&m, 0, sizeof(m));
	memcpy(m.sha, sha, ETH_ALEN);
	memcpy(m.src, src, ETH_ALEN);
	m.spa = inet_addr(spa);
	m.tpa = inet_addr(tpa);
	return m;
}

static void test_probe_conflict(void) {
	uint32_t ip = inet_addr("10.77.0.5");
	struct arp_msg m = msg(evil, evil, "10.77.0.5", "10.77.0.9");
	CHECK(decide_probe_conflict(&m, ip, mine), "a reply from the address");
	m = msg(evil, evil, "0.0.0.0", "10.77.0.5");
	CHECK(decide_probe_conflict(&m, ip, mine),
	      "another host probing the same address");
	m = msg(mine, mine, "0.0.0.0", "10.77.0.5");
	CHECK(!decide_probe_conflict(&m, ip, mine), "our own probe is ignored");
	m = msg(evil, evil, "10.77.0.6", "10.77.0.5");
	CHECK(!decide_probe_conflict(&m, ip, mine),
	      "a request about the address from another sender is not a claim");
	m = msg(evil, evil, "0.0.0.0", "10.77.0.6");
	CHECK(!decide_probe_conflict(&m, ip, mine),
	      "a probe for another address is ignored");
}

static void test_alert(void) {
	struct accept none = {0}, acc;
	enum action act;

	CHECK(decide_alert("C", &none, &act) && act == ACT_STOP,
	      "C stops by default");
	accept_parse(&acc, "C/6");
	CHECK(decide_alert("C", &acc, &act) && act == ACT_WARN,
	      "an accepted C only warns");
	accept_parse(&acc, "C/5");
	CHECK(decide_alert("C", &acc, &act) && act == ACT_STOP,
	      "a C above the approved level stops");
	CHECK(decide_alert("mac-net", &none, &act) && act == ACT_WARN,
	      "mac-net always warns");
	CHECK(decide_alert("Z", &none, &act) == NULL, "an unknown case is nothing");
}

static void test_info(void) {
	struct conflicts cs;
	enum alert_kind k;
	struct alert a;
	conflicts_init(&cs, 0, 0);
	conflict_probe(&cs, inet_addr("10.77.0.1"), evil, evil, 1, &k);
	conflict_probe(&cs, inet_addr("10.77.0.2"), other, evil, 2, &k);

	alert_init(&a, "A");
	decide_claims(&a, &cs);
	CHECK(strcmp(a.info, "case A claim 10.77.0.1@02:aa:aa:aa:aa:01,"
	                     "10.77.0.2@02:bb:bb:bb:bb:01 forged 1") == 0,
	      "claims list every record and the forged hint");

	struct arp_msg m = msg(multicast, other, "10.77.0.5", "10.77.0.5");
	alert_init(&a, "mac-addr");
	decide_probe_info(&a, ALERT_INVALID_MAC, &cs, inet_addr("10.77.0.5"), &m);
	CHECK(strcmp(a.info, "case mac-addr ip 10.77.0.5 claim "
	                     "10.77.0.5@01:00:5e:00:00:01 src 02:bb:bb:bb:bb:01 "
	                     "forged 1") == 0,
	      "mac-addr carries the address, the claim and the frame source");
}

int main(void) {
	test_probe_conflict();
	test_alert();
	test_info();
	return test_summary();
}
