#pragma once

#include <stdint.h>

/*
 * Propagation logic.
 * Implemented in C++, expose through a C API.
 */

void propagate_taint(unsigned int vcpu_idx, uint32_t instr_size, uint32_t instr);

/***
 * Operations on 32 lower bits of registers (RV64 only)
 ***/

// We use target_ulong instead of uint32_t as this is what the _impl functions expect
struct taint_vals_w {
    target_ulong v1;
    target_ulong v2;
    target_ulong t1;
    target_ulong t2;
};

static struct taint_vals_w truncate_vals_taint(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2)
{
    struct taint_vals_w ret = {
        .v1 = SIGN_EXTEND(v1, 31),
        .v2 = SIGN_EXTEND(v2, 31),
        .t1 = SIGN_EXTEND(t1, 31),
        .t2 = SIGN_EXTEND(t2, 31),
    };
    return ret;
}
