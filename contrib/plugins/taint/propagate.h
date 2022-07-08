#pragma once

#include <stdint.h>

/*
 * Propagation logic.
 * Implemented in C++, expose through a C API.
 */

void propagate_taint(unsigned int vcpu_idx, uint32_t instr_size, uint32_t instr);