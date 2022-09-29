#include "common_propagate.h"

#include <qemu-plugin.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "regs.h"
#include "riscv.h"
#include "params.h"
#include "logging.h"

// Compressed instructions also may use these enums and load/store propagation functions.
enum LOAD_TYPE {
    LOAD_LB, LOAD_LH, LOAD_LW,
    LOAD_LBU, LOAD_LHU,
    LOAD_LD, LOAD_LWU,
};
enum STORE_TYPE {
    STORE_SB, STORE_SH, STORE_SW,
    STORE_SD,
};

// To be used by compressed instructions. Do NOT use them for usual function dispatching.
void propagate_taint32_load_impl(unsigned int vcpu_idx, uint8_t rd, target_ulong v1, uint64_t offt, target_ulong t1, enum LOAD_TYPE lt);
void propagate_taint32_store_impl(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, uint64_t offt, target_ulong t1, target_ulong t2, enum STORE_TYPE st);

// Propagation dispatching.
void propagate_taint32_jal(unsigned int vcpu_idx, uint8_t rd);
void propagate_taint32_jalr(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1);
void propagate_taint32__reg_imm_op(unsigned int vcpu_idx, uint32_t instr);
void propagate_taint32__reg_reg_op(unsigned int vcpu_idx, uint32_t instr);
void propagate_taint32__reg_imm_op32(unsigned int vcpu_idx, uint32_t instr);
void propagate_taint32__reg_reg_op32(unsigned int vcpu_idx, uint32_t instr);
