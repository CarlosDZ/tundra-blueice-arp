#include "timing.h"

#include <sys/random.h>
#include <time.h>

uint64_t now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_BOOTTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

uint64_t scaled_ms(uint64_t secs) {
	return secs * 1000 / TUNDRA_BLUEICE_ARP_TIME_SCALE;
}

uint64_t random_ms(uint64_t min, uint64_t max) {
	uint32_t r = 0;
	if (getrandom(&r, sizeof(r), 0) != sizeof(r))
		return min;
	return min + r % (max - min + 1);
}
