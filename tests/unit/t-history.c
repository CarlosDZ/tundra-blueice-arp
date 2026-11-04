#include "guard/conflict.c"
#include "guard/mac.c"
#include "history.c"
#include "test.h"

#define S 1000

static char dir[] = "/tmp/tbia-hist.XXXXXX";
static char path[300];

static const unsigned char evil[ETH_ALEN] = {2, 0xaa, 0xaa, 0xaa, 0xaa, 1};
static const unsigned char other[ETH_ALEN] = {2, 0xbb, 0xbb, 0xbb, 0xbb, 1};

static uint32_t ip(int n) { return htonl((uint32_t)(0x0a4d0000 | n)); }

static void write_file(const char *content) {
	FILE *f = fopen(path, "w");
	if (f) {
		fputs(content, f);
		fclose(f);
	}
}

static void test_roundtrip(void) {
	struct conflicts cs, back;
	enum alert_kind k;
	conflicts_init(&cs, 10 * S, 0);
	conflict_probe(&cs, ip(100), evil, evil, 1 * S, &k);
	conflict_claim(&cs, ip(5), other, evil, 2 * S, &k);

	CHECK(history_save(path, &cs) == 0, "saves the history");
	CHECK(history_load(path, &back, 3 * S) == 0 && back.n == 2,
	      "loads every record back");
	CHECK(back.recs[0].at == 1 * S && back.recs[0].addr == ip(100) &&
	          memcmp(back.recs[0].mac, evil, ETH_ALEN) == 0 &&
	          !back.recs[0].bound && !back.recs[0].forged,
	      "first record intact");
	CHECK(back.recs[1].addr == ip(5) &&
	          memcmp(back.recs[1].mac, other, ETH_ALEN) == 0 &&
	          back.recs[1].bound && back.recs[1].forged,
	      "second record intact, bound and forged");

	FILE *f = fopen(path, "r");
	char line[256] = "";
	if (f) {
		if (!fgets(line, sizeof(line), f))
			line[0] = '\0';
		fclose(f);
	}
	CHECK(strcmp(line, "at 1000 addr 10.77.0.100 mac 02:aa:aa:aa:aa:01 bound "
	                   "0 forged 0\n") == 0,
	      "lines use the key value format");
}

static void test_window(void) {
	struct conflicts cs;
	write_file(
	    "at 1000 addr 10.77.0.1 mac 02:aa:aa:aa:aa:01 bound 0 forged 0\n"
	    "at 300000 addr 10.77.0.2 mac 02:aa:aa:aa:aa:01 bound 0 forged 0\n"
	    "at 999999 addr 10.77.0.3 mac 02:aa:aa:aa:aa:01 bound 0 forged "
	    "0\n");
	CHECK(history_load(path, &cs, CONFLICT_WINDOW_MS + 1001) == 0 &&
	          cs.n == 1 && cs.recs[0].addr == ip(2),
	      "drops records outside the window and from the future");
}

static void test_tolerance(void) {
	struct conflicts cs;
	write_file("at 1 addr 10.77.0.1 mac 02:aa:aa:aa:aa:01 bound 0 forged 0\n"
	           "garbage\n"
	           "at 2 addr 10.77.0.2 bound 0 forged 0\n"
	           "at 3 addr 10.77.0.999 mac 02:aa:aa:aa:aa:01 bound 0 forged 0\n"
	           "at 4 addr 10.77.0.4 mac 02:aa:aa:aa:aa:01 bound 2 forged 0\n"
	           "at 5 addr 10.77.0.5 mac 02:aa:aa:aa:aa:01 bound 1 forged 0 "
	           "future 7\n"
	           "at 6 addr 10.77.0.6 mac 02:aa");
	CHECK(history_load(path, &cs, 10) == 0 && cs.n == 2 &&
	          cs.recs[0].addr == ip(1) && cs.recs[1].addr == ip(5),
	      "drops malformed lines, keeps the rest and ignores unknown keys");

	char many[4096] = "";
	for (int i = 0; i < 20; i++) {
		char l[128];
		snprintf(l, sizeof(l),
		         "at %d addr 10.77.0.%d mac 02:aa:aa:aa:aa:01 bound 0 forged "
		         "0\n",
		         i + 1, i + 1);
		strcat(many, l);
	}
	write_file(many);
	CHECK(history_load(path, &cs, 100) == 0 && cs.n == CONFLICT_MAX &&
	          cs.recs[0].addr == ip(5) &&
	          cs.recs[CONFLICT_MAX - 1].addr == ip(20),
	      "keeps the latest records within the limit");

	unlink(path);
	CHECK(history_load(path, &cs, 100) == 0 && cs.n == 0,
	      "a missing file is an empty history");
}

static void test_writers(void) {
	struct history h1, h2;
	struct conflicts c1, c2, back;
	enum alert_kind k;
	conflicts_init(&c1, 10 * S, 0);
	conflicts_init(&c2, 10 * S, 0);

	CHECK(history_open(&h1, dir, "tdc0") == 0 &&
	          history_open(&h2, dir, "tdc0") == 0,
	      "two writers open the same history");
	history_begin(&h1, &c1, 10 * S);
	CHECK(flock(h2.lockfd, LOCK_EX | LOCK_NB) < 0 && errno == EWOULDBLOCK,
	      "the second writer waits while the first holds the lock");
	conflict_probe(&c1, ip(1), evil, evil, 10 * S, &k);
	history_commit(&h1, &c1);

	history_begin(&h2, &c2, 11 * S);
	CHECK(c2.n == 1, "the second writer sees the first one's record");
	conflict_claim(&c2, ip(2), other, other, 11 * S, &k);
	history_commit(&h2, &c2);

	char hp[300];
	snprintf(hp, sizeof(hp), "%s/tdc0", dir);
	CHECK(history_load(hp, &back, 12 * S) == 0 && back.n == 2,
	      "no record is lost between writers");
	history_close(&h1);
	history_close(&h2);

	char lp[300];
	snprintf(lp, sizeof(lp), "%s/tdc0.lock", dir);
	unlink(hp);
	unlink(lp);

	char longname[300];
	memset(longname, 'x', sizeof(longname) - 1);
	longname[sizeof(longname) - 1] = '\0';
	CHECK(history_open(&h1, dir, longname) < 0, "a path too long is refused");
}

int main(void) {
	if (!freopen("/dev/null", "w", stderr) || !mkdtemp(dir))
		return 1;
	snprintf(path, sizeof(path), "%s/hist", dir);

	test_roundtrip();
	test_window();
	test_tolerance();
	test_writers();

	unlink(path);
	rmdir(dir);
	return test_summary();
}
