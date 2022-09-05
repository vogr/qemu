#pragma once

#include <stdint.h>

#include <sys/types.h>

#include "xlen.h"

struct src_regs_values
{
    target_ulong v1;
    target_ulong v2;
};


target_ulong get_one_reg_value(unsigned int vcpu_idx, char r);
struct src_regs_values get_src_reg_values(unsigned int vcpu_idx, char rs1, char rs2);