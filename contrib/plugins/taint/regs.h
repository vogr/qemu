#pragma once

#include <stdint.h>

#include <sys/types.h>

struct src_regs_values
{
    uint64_t v1;
    uint64_t v2;
};


uint64_t get_one_reg_value(char r);
struct src_regs_values get_src_reg_values(char rs1, char rs2);