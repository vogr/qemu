#pragma once

#include <sys/types.h>

// Memory address where emulation starts
// has to match with the link script !
#define BASE_PHYS_ADDR 0x80000000

// Size of the memory
#define PHYS_MEM_SIZE 128 * 1024 * 1024 // 128 MiB
