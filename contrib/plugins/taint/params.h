#pragma once

#include <stdint.h>
#include <sys/types.h>

#include <pthread.h>

// Shadow memory
// mmap and  0-initialize at startup
extern uint8_t * shadow_mem;
extern size_t shadow_mem_size;

// Shadow registers. 32 integer registers, 64b per register.
// NOTE: x0 cannot be tainted as it is the hardwired 0 value.
extern uint64_t shadow_regs[32];

extern pthread_mutex_t shadow_lock;