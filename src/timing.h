#ifndef TUNDRA_TIMING_H
#define TUNDRA_TIMING_H

#include <stdint.h>

uint64_t now_ms(void);
uint64_t wall_ms(void);
uint64_t scaled_ms(uint64_t secs);
uint64_t random_ms(uint64_t min, uint64_t max);

#endif
