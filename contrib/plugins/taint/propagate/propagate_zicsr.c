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

/**
 * Opcode dispatch
 */

void propagate_taint32__csr_op(unsigned int vcpu_idx, uint32_t instr)
{
    // If the source register is tainted, then taint the PC.
    // We assume that the immediate is not tainted.
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint8_t f3  = INSTR32_GET_FUNCT3(instr);

    target_ulong t1 = shadow_regs[rs1];

    switch (f3) {
        case INSTR32_F3_CSRRW:
        case INSTR32_F3_CSRRS:
        case INSTR32_F3_CSRRC:
            if (t1)
                taint_pc(vcpu_idx);
            break;
        case INSTR32_F3_CSRRWI:
        case INSTR32_F3_CSRRSI:
        case INSTR32_F3_CSRRCI:
            break;
        default:
            fprintf(stderr, "Unknown opcode for Zicsr instr: 0x%" PRIx32 "\n", instr);
            break;
    }
}
