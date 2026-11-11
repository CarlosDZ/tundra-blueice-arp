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
	enum blueice_action act;

	CHECK(decide_alert("C", &none, &act) && act == BLUEICE_STOP,
	      "C stops by default");
	accept_parse(&acc, "C/6");
	CHECK(decide_alert("C", &acc, &act) && act == BLUEICE_WARN,
	      "an accepted C only warns");
	accept_parse(&acc, "C/5");
	CHECK(decide_alert("C", &acc, &act) && act == BLUEICE_STOP,
	      "a C above the approved level stops");
	CHECK(decide_alert("mac-net", &none, &act) && act == BLUEICE_WARN,
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
	CHECK(strcmp(a.line.info, "case A claim 10.77.0.1@02:aa:aa:aa:aa:01,"
	                     "10.77.0.2@02:bb:bb:bb:bb:01 forged 1") == 0,
	      "claims list every record and the forged hint");

	struct arp_msg m = msg(multicast, other, "10.77.0.5", "10.77.0.5");
	alert_init(&a, "mac-addr");
	decide_addr_info(&a, ALERT_INVALID_MAC, &cs, inet_addr("10.77.0.5"), &m);
	CHECK(strcmp(a.line.info, "case mac-addr ip 10.77.0.5 claim "
	                     "10.77.0.5@01:00:5e:00:00:01 src 02:bb:bb:bb:bb:01 "
	                     "forged 1") == 0,
	      "mac-addr carries the address, the claim and the frame source");
}

static void test_watch_target(void) {
	uint32_t ip = inet_addr("10.77.0.5"), gw = inet_addr("10.77.0.1");
	struct arp_msg m = msg(evil, evil, "10.77.0.5", "10.77.0.5");
	CHECK(decide_watch_target(&m, ip, gw, mine) == T_ADDR,
	      "a claim on the address in use");
	m = msg(evil, evil, "10.77.0.1", "10.77.0.5");
	CHECK(decide_watch_target(&m, ip, gw, mine) == T_GW,
	      "a message from the gateway address");
	CHECK(decide_watch_target(&m, ip, 0, mine) == T_NONE,
	      "without a gateway its address is not watched");
	m = msg(multicast, multicast, "10.77.0.9", "10.77.0.9");
	CHECK(decide_watch_target(&m, ip, gw, mine) == T_NET,
	      "a crafted MAC elsewhere on the network");
	m = msg(evil, multicast, "10.77.0.9", "10.77.0.9");
	CHECK(decide_watch_target(&m, ip, gw, mine) == T_NET,
	      "a crafted frame source elsewhere on the network");
	m = msg(evil, other, "10.77.0.9", "10.77.0.9");
	CHECK(decide_watch_target(&m, ip, gw, mine) == T_NONE,
	      "a valid but proxied frame elsewhere is not judged");
	m = msg(mine, mine, "10.77.0.5", "10.77.0.5");
	CHECK(decide_watch_target(&m, ip, gw, mine) == T_NONE,
	      "our own announcements are ignored");
}

static void test_warn_once(void) {
	struct warned w = {0};
	CHECK(decide_warn_once(&w, "mac-net", evil), "the first warning is shown");
	CHECK(!decide_warn_once(&w, "mac-net", evil),
	      "the same case and MAC is shown once");
	CHECK(decide_warn_once(&w, "mac-net", other),
	      "another MAC is a new warning");
	CHECK(decide_warn_once(&w, "C", evil), "another case is a new warning");
}

static void test_watch_info(void) {
	struct conflicts cs;
	struct gateway g = {0};
	enum alert_kind k;
	struct alert a;

	conflicts_init(&cs, 0, 0);
	conflict_claim(&cs, inet_addr("10.77.0.5"), evil, evil, 1, &k);
	alert_init(&a, "C");
	decide_addr_info(&a, ALERT_CLAIMED, &cs, inet_addr("10.77.0.5"), NULL);
	CHECK(strcmp(a.line.info, "case C ip 10.77.0.5 claim "
	                     "10.77.0.5@02:aa:aa:aa:aa:01 forged 0") == 0,
	      "C carries the address in use and its claims");

	memcpy(g.mac, other, ETH_ALEN);
	g.known = 1;
	memcpy(g.seen[0], other, ETH_ALEN);
	memcpy(g.seen[1], evil, ETH_ALEN);
	g.nseen = 2;
	alert_init(&a, "D");
	decide_gw_info(&a, &g, inet_addr("10.77.0.1"), NULL);
	CHECK(strcmp(a.line.info, "case D gw 10.77.0.1 known 02:bb:bb:bb:bb:01 seen "
	                     "02:bb:bb:bb:bb:01,02:aa:aa:aa:aa:01 forged 0") == 0,
	      "D carries the gateway, the known MAC and every MAC seen");

	struct arp_msg m = msg(multicast, evil, "10.77.0.1", "10.77.0.5");
	alert_init(&a, "mac-gw");
	decide_gw_info(&a, &g, inet_addr("10.77.0.1"), &m);
	CHECK(strcmp(a.line.info, "case mac-gw gw 10.77.0.1 known 02:bb:bb:bb:bb:01 "
	                     "seen 01:00:5e:00:00:01 src 02:aa:aa:aa:aa:01 "
	                     "forged 1") == 0,
	      "mac-gw carries the crafted MAC and the frame source");

	m = msg(multicast, multicast, "10.77.0.9", "10.77.0.9");
	alert_init(&a, "mac-net");
	decide_net_info(&a, &m);
	CHECK(strcmp(a.line.info, "case mac-net ip 10.77.0.9 sha 01:00:5e:00:00:01 "
	                     "src 01:00:5e:00:00:01 forged 0") == 0,
	      "mac-net carries the sender and the frame source");
}

int main(void) {
	test_probe_conflict();
	test_alert();
	test_info();
	test_watch_target();
	test_warn_once();
	test_watch_info();
	return test_summary();
}
