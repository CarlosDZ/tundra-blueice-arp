#include "accept.c"
#include "alert.c"
#include "test.h"

int main(void) {
	struct accept a;

	CHECK(accept_parse(&a, "C/6,D/8") == 0 && a.n == 2, "parses two cases");
	CHECK(accept_covers(&a, "C", 6) && accept_covers(&a, "C", 5),
	      "covers the same case at the approved level or lower");
	CHECK(!accept_covers(&a, "C", 7), "a higher level is not covered");
	CHECK(accept_covers(&a, "D", 8), "covers every listed case");
	CHECK(!accept_covers(&a, "A", 4), "another case is not covered");

	CHECK(accept_parse(&a, "mac-addr/10") == 0 &&
	          accept_covers(&a, "mac-addr", 10),
	      "level 10 is accepted");

	const char *bad[] = {"",    "C",       "C/",   "C/0", "C/11", "C/6x",
	                     "Z/3", "C/6,C/7", "C/-1", "/6",  "C/06", "C 6"};
	int refused = 1;
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
		if (accept_parse(&a, bad[i]) == 0)
			refused = 0;
	CHECK(refused, "malformed, unknown, repeated or out of range is refused");

	struct accept empty = {0};
	CHECK(!accept_covers(&empty, "C", 1), "nothing is covered by default");
	return test_summary();
}
