#include "test.h"
#include "timing.c"

int main(void) {
	CHECK(scaled_ms(10) == 10000, "seconds become milliseconds at scale 1");

	int in_range = 1;
	for (int i = 0; i < 200; i++) {
		uint64_t r = random_ms(1000, 2000);
		if (r < 1000 || r > 2000)
			in_range = 0;
	}
	CHECK(in_range, "random delays stay within their bounds");
	CHECK(random_ms(5, 5) == 5, "an empty range returns its only value");

	uint64_t a = now_ms(), b = now_ms();
	CHECK(a > 0 && b >= a, "the clock is monotonic");
	return test_summary();
}
