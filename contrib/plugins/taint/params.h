#pragma once

#include <stdint.h>

#include <sys/types.h>

// Memory address where emulation starts
// has to match with the link script !
static size_t const BASE_PHYS_ADDR =  0x80000000;

// Size of the memory
static size_t const PHYS_MEM_SIZE = 128 * 1024 * 1024; // 128 MiB

// Shadow memory
// mmap and  0-initialize at startup
extern uint8_t * shadow_mem;

// Shadow registers. 32 integer registers, 64b per register.
// NOTE: x0 cannot be tainted as it is the hardwired 0 value.
extern uint64_t shadow_regs[32];