#include "propagate.h"
#include "propagate_i.h"
#include "propagate_m.h"
#include "propagate_f.h"
#include "propagate_c.h"
#include "propagate_zicsr.h"

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

// NOTE: When manipulating register values, and memory values, we are assuming
// that the host and target have the same endianess. For our purposes, all our
// platforms are little-endian (ie x86 host and RISCV target).



static void propagate_taint32(unsigned int vcpu_idx, uint32_t instr)
{
#ifndef NDEBUG
    // the lsb are 0b11 for all 32b instructions
    uint8_t opcode_lo = INSTR32_OPCODE_GET_LO(instr);
    assert(opcode_lo == 0b11);
#endif

    uint8_t opcode_hi = INSTR32_OPCODE_GET_HI(instr);

    // the opcode always ends with 0b11, dispatch on the higher bits
    // to make it easier for the compiler to create a jump table.
    switch (opcode_hi)
    {
    case INSTR32_OPCODE_HI_LOAD:
        propagate_taint32_load(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_LOAD_FP:
        propagate_taint32_load_fp(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_MISC_MEM:
        propagate_taint32_fence(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_OP_IMM:
        propagate_taint32__reg_imm_op(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_AUIPC:
        propagate_taint32_auipc(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_OP_IMM_32:
        propagate_taint32__reg_imm_op32(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_STORE:
        propagate_taint32__store(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_STORE_FP:
        propagate_taint32__store_fp(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_AMO: // FIXME: no support for atomic operations (A extension)
        break;

    case INSTR32_OPCODE_HI_OP:
        propagate_taint32__reg_reg_op(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_LUI:
        propagate_taint32_lui(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_OP_32:
        propagate_taint32__reg_reg_op32(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_FP_MADD:
    case INSTR32_OPCODE_HI_FP_MSUB:
    case INSTR32_OPCODE_HI_FP_NMSUB:
    case INSTR32_OPCODE_HI_FP_NMADD:
        propagate_taint32__fp_madd_msub_nmadd_nmsub(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_FP_OP: 
        propagate_taint32__fp_op(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_BRANCH:
        propagate_taint32__branch(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_JALR:
        uint8_t rd = INSTR32_RD_GET(instr);
        uint8_t rs1 = INSTR32_RS1_GET(instr);
        propagate_taint32_jalr(vcpu_idx, rd, rs1);
        break;

    case INSTR32_OPCODE_HI_JAL:
        propagate_taint32_jal(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_SYSTEM:
        propagate_taint32__csr_op(vcpu_idx, instr);
        break;

    default:
        fprintf(stderr, "Unknown opcode for instr: 0x%" PRIx32 "\n", instr);
        break;
    }
}

/***
 * Opcode dispatch entrypoint
 ***/

void propagate_taint(unsigned int vcpu_idx, uint32_t instr_size, uint32_t instr)
{
    switch (instr_size)
    {
    case 16:
        propagate_taint16(vcpu_idx, (uint16_t)instr);
        break;
    case 32:
        propagate_taint32(vcpu_idx, instr);
        break;
    default:
        fprintf(stderr, "ERROR: Unexpected instruction size %" PRIu32 "B for instr: 0x%" PRIx32 "\n", instr_size, instr);
        exit(1);
        break;
    }
}


