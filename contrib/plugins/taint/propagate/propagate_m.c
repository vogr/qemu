#include "propagate.h"

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

/***
 * M extension
 ***/

static void propagate_taint_muldiv(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong tout = propagate_taint_op__lazy(t1, t2);

    shadow_regs[rd] = tout;
}

