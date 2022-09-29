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

void propagate_taint32__reg_imm_op(unsigned int vcpu_idx, uint32_t instr);
void propagate_taint32__reg_reg_op(unsigned int vcpu_idx, uint32_t instr);
void propagate_taint32__reg_imm_op32(unsigned int vcpu_idx, uint32_t instr);
void propagate_taint32__reg_reg_op32(unsigned int vcpu_idx, uint32_t instr);
