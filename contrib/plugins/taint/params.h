#pragma once

#include <stdint.h>
#include <sys/types.h>

#include "xlen.h"

// Shadow memory
// mmap and  0-initialize at startup
extern uint8_t * shadow_mem;
extern size_t shadow_mem_size;

// Shadow registers. 32 integer registers, XLEN bytes per register.
// NOTE: x0 cannot be tainted as it is the hardwired 0 value.
extern target_ulong shadow_regs[32];
extern target_fplong shadow_fpregs[32];

// To make the PC tainted.
extern void taint_pc(int vcpu_idx);
// To read whether the PC is tainted.
extern target_ulong get_pc_taint();
