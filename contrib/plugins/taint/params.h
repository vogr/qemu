#pragma once

#include <stdint.h>
#include <sys/types.h>

#include <pthread.h>

#include "xlen.h"

// Shadow memory
// mmap and  0-initialize at startup
extern uint8_t * shadow_mem;
extern size_t shadow_mem_size;

// Shadow registers. 32 integer registers, XLEN bytes per register.
// NOTE: x0 cannot be tainted as it is the hardwired 0 value.
extern target_ulong shadow_regs[32];

extern pthread_mutex_t shadow_lock;