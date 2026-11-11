#include "alert.c"
#include "test.h"

static void test_table(void) {
	const struct alert_def *d = alert_def("C");
	CHECK(d && d->action == BLUEICE_STOP && d->level == 6, "C: stop, level 6");
	d = alert_def("mac-net");
	CHECK(d && d->action == BLUEICE_WARN && d->level == 2,
	      "mac-net: warn, level 2");
	CHECK(alert_def("D")->level == 8 && alert_def("mac-gw")->level == 8 &&
	          alert_def("mac-addr")->level == 7 && alert_def("A")->level == 4 &&
	          alert_def("B")->level == 4,
	      "levels of the remaining cases");
	CHECK(alert_def("Z") == NULL, "an unknown case has no definition");
}

static void test_format(void) {
	char line[1024];
	struct alert a;

	alert_init(&a, "D");
	alert_add(&a, "gw", "10.77.0.1");
	alert_add(&a, "known", "52:54:00:ac:c9:ff");
	alert_add(&a, "seen", "02:bb:bb:bb:bb:bb");
	alert_add(&a, "forged", "1");
	CHECK(alert_format(line, sizeof(line), &a, BLUEICE_STOP, "enp8s0",
	                   1762171512347ull) == 0 &&
	          strcmp(line, "alert 111/8 stop by tundra-blueice-arp on enp8s0 "
	                       "ts 1762171512.347 reply force,disconnect info "
	                       "case D gw 10.77.0.1 known 52:54:00:ac:c9:ff seen "
	                       "02:bb:bb:bb:bb:bb forged 1 -- gateway "
	                       "impersonation") == 0,
	      "stop line");

	alert_init(&a, "C");
	alert_add(&a, "ip", "10.77.0.5");
	CHECK(alert_format(line, sizeof(line), &a, BLUEICE_WARN, "enp8s0", 5) ==
	              0 &&
	          strstr(line, "alert 111/6 warn ") == line &&
	          strstr(line, " ts 0.005 ") &&
	          strstr(line, " reply ack,disconnect "),
	      "an accepted case keeps its level and is answered with ack");

	alert_init(&a, "mac-net");
	alert_add(&a, "ssid", "a b");
	CHECK(alert_format(line, sizeof(line), &a, BLUEICE_WARN, "wl an0", 0) ==
	              0 &&
	          strstr(line, " on wl%20an0 ") && strstr(line, " ssid a%20b "),
	      "interface and values are encoded");

	CHECK(alert_init(&a, "Z") < 0 &&
	          alert_format(line, sizeof(line), &a, BLUEICE_STOP, "enp8s0", 0) <
	              0,
	      "an unknown case cannot be formatted");

	alert_init(&a, "A");
	alert_add(&a, "claim", "");
	CHECK(alert_format(line, sizeof(line), &a, BLUEICE_STOP, "enp8s0", 0) < 0,
	      "an empty value spoils the alert");

	alert_init(&a, "B");
	for (int i = 0; i < 100; i++)
		alert_add(&a, "claim", "10.77.0.100@02:aa:aa:aa:aa:01");
	CHECK(a.line.bad && alert_format(line, sizeof(line), &a, BLUEICE_STOP,
	                                 "enp8s0", 0) < 0,
	      "an info that does not fit spoils the alert");

	alert_init(&a, "A");
	CHECK(alert_format(line, 20, &a, BLUEICE_STOP, "enp8s0", 0) < 0,
	      "a line that does not fit is refused");
}

int main(void) {
	test_table();
	test_format();
	return test_summary();
}
