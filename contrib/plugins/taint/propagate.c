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

// NOTE: When manipulating register values, and memory values, we are assuming
// that the host and target have the same endianess. For our purposes, all our
// platforms are little-endian (ie x86 host and RISCV target).


/***
 * Opcode dispatch (uncompressed instructions)
 ***/

static void propagate_taint32__reg_imm_op(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);

    // imm and f7/shamt bits overlap, only one should be used!
    uint16_t imm = INSTR32_I_IMM_0_11_GET(instr);

    // /!\ shamt is read differently on RV32 and RV64!
    // this determines how many bits of the imm are read for dispatch
#ifdef TARGET_RISCV64
    uint32_t f6 = INSTR32_GET_FUNCT7(instr) >> 1;
#else
    uint32_t f7 = INSTR32_GET_FUNCT7(instr);
#endif

    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);

    if (rd == 0)
    {
        // x0 cannot be tainted
        return;
    }

    switch(f3)
    {
        case INSTR32_F3_ADDI:
        {
            propagate_taint_ADDI(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_SLTI:
        {
            propagate_taint_SLTI(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_SLTIU:
        {
            propagate_taint_SLTIU(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_XORI:
        {
            propagate_taint_XORI(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_ORI:
        {
            propagate_taint_ORI(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_ANDI:
        {
            propagate_taint_ANDI(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_SLLI__:
        {
#ifdef TARGET_RISCV64
            bool is_slli = (f6 == INSTR32_F6_SLLI_RV64);
#else
            bool is_slli = (f7 == INSTR32_F7_SLLI_RV32);
#endif
            if (is_slli)
            {
                propagate_taint_SLLI(vcpu_idx, rd, rs1, imm);
            }
            else
            {
                fprintf(stderr, "Malformed instruction, unknown f6/f7 for f3=SLLI: 0x%" PRIx32 "\n", instr);
            }
            break;
        }
        case INSTR32_F3_SRLI__SRAI:
        {
#ifdef TARGET_RISCV64
            bool is_srli = (f6 == INSTR32_F6_SRLI_RV64);
            bool is_srai = (f6 == INSTR32_F6_SRAI_RV64);
#else
            bool is_srli = (f7 == INSTR32_F7_SRLI_RV32);
            bool is_srai = (f7 == INSTR32_F7_SRAI_RV32);
#endif
            if (is_srli)
            {
                propagate_taint_SRLI(vcpu_idx, rd, rs1, imm);
            }
            else if (is_srai)
            {
                propagate_taint_SRAI(vcpu_idx, rd, rs1, imm);
            }
            else
            {
                fprintf(stderr, "Malformed instruction, unknown f6/f7 for f3=SRLI_SRAI: 0x%" PRIx32 "\n", instr);
            }

            break;
        }
        default:
        {
            fprintf(stderr, "Unknown reg-imm op f3 for instr: 0x%" PRIx32 "\n", instr);
            break;
        }
    }
}



static void propagate_taint32__reg_reg_op(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);
    uint8_t f7 = INSTR32_GET_FUNCT7(instr);

    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint8_t rs2 = INSTR32_RS2_GET(instr);

    if (rd == 0)
    {
        // x0 cannot be tainted
        return;
    }

    switch (f3)
    {
    case INSTR32_F3_ADD_SUB_MUL:
    {
        if (f7 == INSTR32_F7_ADD)
            propagate_taint_ADD(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_SUB)
            propagate_taint_SUB(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_MUL)
            propagate_taint_MUL(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=ADD_SUB_MUL: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_SLL_MULH:
    {
        if (f7 == INSTR32_F7_SLL)
            propagate_taint_SLL(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_MULH)
            propagate_taint_MUL(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLL_MULH: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_SLT_MULHSU:
    {
        if (f7 == INSTR32_F7_SLT)
            propagate_taint_SLT(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_MULHSU)
            propagate_taint_MUL(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLT_MULHSU: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_SLTU_MULHU:
    {
        if (f7 == INSTR32_F7_SLTU)
            propagate_taint_SLTU(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_MULHU)
            propagate_taint_MUL(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLTU_MULHU: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_XOR_DIV:
    {
        if (f7 == INSTR32_F7_XOR)
            propagate_taint_XOR(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_DIV)
            propagate_taint_MUL_DIV(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=XOR_DIV: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_SRL_SRA_DIVU:
    {
        if (f7 == INSTR32_F7_SRL)
            propagate_taint_SRL(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_SRA)
            propagate_taint_SRA(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_DIVU)
            propagate_taint_MUL_DIV(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=SRL_SRA_DIVU: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_OR_REM:
    {
        if (f7 == INSTR32_F7_OR)
            propagate_taint_OR(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_REM)
            propagate_taint_MUL_DIV(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=OR_REM: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_AND_REMU:
    {
        if (f7 == INSTR32_F7_AND)
            propagate_taint_AND(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_REMU)
            propagate_taint_MUL_DIV(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=OR_REM: 0x%" PRIx32 "\n", instr);
        break;
    }
    default:
        fprintf(stderr, "Unknown reg-reg op f3 for instr: 0x%" PRIx32 "\n", instr);
        break;
    }
}

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

// TODO Move to propagate_i.c, section RV64

static void propagate_taint_ADDW(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    struct taint_vals_w in_w = truncate_vals_taint(vals.v1, vals.v2, t1, t2);

    target_ulong tout_low = propagate_taint__add(in_w.v1, in_w.v2, in_w.t1, in_w.t2);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate ADDW(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);
}

static void propagate_taint_ADDIW(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // Acceptable precision is important bc "mov rd,rs" is just an alias for "addi rd,rs,0"
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

    target_ulong t1 = shadow_regs[rs1];

    struct taint_vals_w in_w = truncate_vals_taint(v1, imm, t1, 0);

    target_ulong tout_low = propagate_taint__add(in_w.v1, in_w.v2, in_w.t1, in_w.t2);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate ADDIW(r%d=0x%" PRIxXLEN ",imm=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, v1, imm, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);
}

static void propagate_taint_SUBW(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    struct taint_vals_w in_w = truncate_vals_taint(vals.v1, vals.v2, t1, t2);

    target_ulong tout_low = propagate_taint__sub(in_w.v1, in_w.v2, in_w.t1, in_w.t2);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SUBW(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);
}


static void propagate_taint_SLLW(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct taint_vals_w in_w = truncate_vals_taint(vals.v1, vals.v2, t1, t2);

    // /!\ SHAMT_SIZE is fixed as if RV32, i.e. to 5
    target_ulong tout_low = propagate_taint_sll_impl(in_w.v1, in_w.t1, in_w.v2, in_w.t2, 5);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLLW(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);

}



static void propagate_taint_SLLIW(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint64_t imm)
{
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    struct taint_vals_w in_w = truncate_vals_taint(v1, imm, t1, 0);

    // /!\ SHAMT_SIZE is fixed as if RV32, i.e. to 5
    target_ulong tout_low = propagate_taint_sll_impl(in_w.v1, in_w.t1, in_w.v2, in_w.t2, 5);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLLIW(0x%" PRIxXLEN ", imm=0x%" PRIx16 ") -> r%" PRIu8 "\n", v1, imm, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);


}



static void propagate_taint_SRLW(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct taint_vals_w in_w = truncate_vals_taint(vals.v1, vals.v2, t1, t2);

    // /!\ SHAMT_SIZE is fixed as if RV32, i.e. to 5
    target_ulong tout_low = propagate_taint_srl_impl(in_w.v1, in_w.t1, in_w.v2, in_w.t2, 5);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SRLW(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);

}



static void propagate_taint_SRLIW(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint64_t imm)
{
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    struct taint_vals_w in_w = truncate_vals_taint(v1, imm, t1, 0);

    // /!\ SHAMT_SIZE is fixed as if RV32, i.e. to 5
    target_ulong tout_low = propagate_taint_srl_impl(in_w.v1, in_w.t1, in_w.v2, in_w.t2, 5);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SRLIW(0x%" PRIxXLEN ", imm=0x%" PRIx16 ") -> r%" PRIu8 "\n", v1, imm, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);


}


static void propagate_taint_SRAW(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct taint_vals_w in_w = truncate_vals_taint(vals.v1, vals.v2, t1, t2);

    // /!\ SHAMT_SIZE is fixed as if RV32, i.e. to 5
    target_ulong tout_low = propagate_taint_sra_impl(in_w.v1, in_w.t1, in_w.v2, in_w.t2, 5);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SRAW(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);

}



static void propagate_taint_SRAIW(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint64_t imm)
{
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    struct taint_vals_w in_w = truncate_vals_taint(v1, imm, t1, 0);

    // /!\ SHAMT_SIZE is fixed as if RV32, i.e. to 5
    target_ulong tout_low = propagate_taint_sra_impl(in_w.v1, in_w.t1, in_w.v2, in_w.t2, 5);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SRLAW(0x%" PRIxXLEN ", imm=0x%" PRIx16 ") -> r%" PRIu8 "\n", v1, imm, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);
}


/***
 * Opcode dispatch (uncompressed instructions, wordsize instructions -- RV64I only).
 ***/

static void propagate_taint32__reg_imm_op32(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);

    // imm and f7/shamt bits overlap, only one should be used!
    uint16_t imm = INSTR32_I_IMM_0_11_GET(instr);
    uint32_t f7 = INSTR32_GET_FUNCT7(instr);
    // note that shamt is NOT sign extended ()
    uint8_t shamt = INSTR32_I_SHAMT_GET_FIVE(instr);


    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);

    if (rd == 0)
    {
        // x0 cannot be tainted
        return;
    }

    switch(f3)
    {
        case INSTR32_F3_ADDIW:
        {
            // no f7 to check
            propagate_taint_ADDIW(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_SLLIW:
        {
            if (f7 == INSTR32_F7_SLLIW)
                propagate_taint_SLLIW(vcpu_idx, rd, rs1, shamt);
            else
                fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLLIW: 0x%" PRIx32 "\n", instr);
            break;
        }
        case INSTR32_F3_SRLIW_SRAIW:
        {
            if (f7 == INSTR32_F7_SRLIW)
                propagate_taint_SRLIW(vcpu_idx, rd, rs1, shamt);
            else if (f7 == INSTR32_F7_SRAIW)
                propagate_taint_SRAIW(vcpu_idx, rd, rs1, shamt);
            else
                fprintf(stderr, "Malformed instruction, unknown f7 for f3=SRLIW_SRAIW: 0x%" PRIx32 "\n", instr);
            break;
        }
        default:
        {
            fprintf(stderr, "Unknown wordsize reg-imm op f3 for instr: 0x%" PRIx32 "\n", instr);
            break;
        }
    }
}

static void propagate_taint32__reg_reg_op32(unsigned int vcpu_idx, uint32_t instr)
{
    // FIXME: Support for M extension (MULW, DIVW, ...)
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);
    uint8_t f7 = INSTR32_GET_FUNCT7(instr);

    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint8_t rs2 = INSTR32_RS2_GET(instr);

    if (rd == 0)
    {
        // x0 cannot be tainted
        return;
    }

    switch (f3)
    {
        case INSTR32_F3_ADDW_SUBW:
        {
            if (f7 == INSTR32_F7_ADDW)
                propagate_taint_ADDW(vcpu_idx, rd, rs1, rs2);
            else if (f7 == INSTR32_F7_SUBW)
                propagate_taint_SUBW(vcpu_idx, rd, rs1, rs2);
            else
                fprintf(stderr, "Malformed instruction, unknown f7 for f3=ADDW_SUBW: 0x%" PRIx32 "\n", instr);
            break;
        }
        case INSTR32_F3_SLLW:
        {
            if (f7 == INSTR32_F7_SLLW)
                propagate_taint_SLLW(vcpu_idx, rd, rs1, rs2);
            else
                fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLLW: 0x%" PRIx32 "\n", instr);

            break;
        }
        case INSTR32_F3_SRLW_SRAW:
        {
            if (f7 == INSTR32_F7_SRLW)
                propagate_taint_SRLW(vcpu_idx, rd, rs1, rs2);
            else if (f7 == INSTR32_F7_SRAW)
                propagate_taint_SRAW(vcpu_idx, rd, rs1, rs2);
            else
                fprintf(stderr, "Malformed instruction, unknown f7 for f3=SRLW_SRAW: 0x%" PRIx32 "\n", instr);
            break;
        }
        default:
        {
            fprintf(stderr, "Unknown wordsize reg-reg op f3 for instr: 0x%" PRIx32 "\n", instr);
            break;
        }
    }
}

/**
 * Floating-point madd, msub, nmadd, nmsub
 */

static void propagate_taint32__fp_madd_msub_nmadd_nmsub_impl(unsigned int vcpu_idx, uint8_t rd, target_fplong t1, target_fplong t2, target_fplong t3)
{
    if (t1 | t2 | t3)
        shadow_fpregs[rd] = -1ULL;
    else
        shadow_fpregs[rd] = 0;
}

static void propagate_taint32__fp_madd_msub_nmadd_nmsub(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint8_t rs2 = INSTR32_RS2_GET(instr);
    uint8_t rs3 = INSTR32_RS3_GET(instr);

    target_fplong t1 = shadow_fpregs[rs1];
    target_fplong t2 = shadow_fpregs[rs2];
    target_fplong t3 = shadow_fpregs[rs3];

    propagate_taint32__fp_madd_msub_nmadd_nmsub_impl(vcpu_idx, rd, t1, t2, t3);
}

/**
 * Floating-point ops
 */

enum FOP_TYPE {
    FOP_FUNC7_FADD_S                 = 0b0000000,
    FOP_FUNC7_FSUB_S                 = 0b0000100,
    FOP_FUNC7_FMUL_S                 = 0b0001000,
    FOP_FUNC7_FDIV_S                 = 0b0001100,
    FOP_FUNC7_FSQRT_S                = 0b0101100,
    FOP_FUNC7_FSGNJ_S                = 0b0010000,
// FOP_FUNC7_FSGNJN_S  0b0010000
// FOP_FUNC7_FSGNJX_S  0b0010000
    FOP_FUNC7_FMIN_S                 = 0b0010100,
// FOP_FUNC7_FMAX_S    0b0010100
    FOP_FUNC7_FCVT_W_S               = 0b1100000,
// FOP_FUNC7_FCVT_WU_S 0b1100000
    FOP_FUNC7_FMV_X_W__OR__FCLASS_S  = 0b1110000,
    FOP_FUNC7_FEQ_S                  = 0b1010000,
// FOP_FUNC7_FLT_S     0b1010000
// FOP_FUNC7_FLE_S     0b1010000
// FOP_FUNC7_FCLASS_S                = 0b1110000,
    FOP_FUNC7_FCVT_S_W               = 0b1101000,
// FOP_FUNC7_FCVT_S_WU 0b1101000
    FOP_FUNC7_FMV_W_X                = 0b1111000,

    FOP_FUNC7_FADD_D                 = 0b0000001,
    FOP_FUNC7_FSUB_D                 = 0b0000101,
    FOP_FUNC7_FMUL_D                 = 0b0001001,
    FOP_FUNC7_FDIV_D                 = 0b0001101,
    FOP_FUNC7_FSQRT_D                = 0b0101101,
    FOP_FUNC7_FSGNJ_D                = 0b0010001,
// FOP_FUNC7_FSGNJN_D  0b0010001
// FOP_FUNC7_FSGNJX_D  0b0010001
    FOP_FUNC7_FMIN_D                 = 0b0010101,
// FOP_FUNC7_FMAX_D    0b0010101
    FOP_FUNC7_FCVT_S_D               = 0b0100000,
    FOP_FUNC7_FCVT_D_S               = 0b0100001,
    FOP_FUNC7_FEQ_D                  = 0b1010001,
// FOP_FUNC7_FLT_D     0b1010001
// FOP_FUNC7_FLE_D     0b1010001
    FOP_FUNC7_FCLASS_D               = 0b1110001,
    FOP_FUNC7_FCVT_W_D               = 0b1100001,
// FOP_FUNC7_FCVT_WU_D 0b1100001
    FOP_FUNC7_FCVT_D_W               = 0b1101001,
// FOP_FUNC7_FCVT_D_WU 0b1101001
};

static void propagate_taint32__fp_regop_impl(unsigned int vcpu_idx, uint8_t rd, target_fplong t1, target_fplong t2) {
    if (t1 | t2)
        shadow_fpregs[rd] = -1ULL;
    else
        shadow_fpregs[rd] = 0;
}
static void propagate_taint32__fp_sqrt_impl(unsigned int vcpu_idx, uint8_t rd, target_fplong t1) {
    if (t1)
        shadow_fpregs[rd] = -1ULL;
    else
        shadow_fpregs[rd] = 0;
}
static void propagate_taint32__fp_to_int_impl(unsigned int vcpu_idx, uint8_t rd, target_fplong t1) {
    // The sign extension ensures that the complete destination register is becoming tainted.
    if (t1)
        shadow_regs[rd] = -1ULL;
    else
        shadow_regs[rd] = 0;
}
static void propagate_taint32__fp_from_int_impl(unsigned int vcpu_idx, uint8_t rd, target_ulong t1) {
    if (t1)
        shadow_fpregs[rd] = (uint32_t)(-1);
    else
        shadow_fpregs[rd] = 0;
}
static void propagate_taint32__fp_cmp_impl(unsigned int vcpu_idx, uint8_t rd, target_fplong t1, target_fplong t2) {
    // Comparisons that write 0 or 1 to an integer register.
    if (t1 | t2)
        shadow_regs[rd] = 1;
    else
        shadow_regs[rd] = 0;
}
static void propagate_taint32__fp_mv_impl(unsigned int vcpu_idx, uint8_t rd, target_fplong t1) {
    if (t1)
        shadow_fpregs[rd] = 1;
    else
        shadow_fpregs[rd] = 0;
}

static void propagate_taint32__fp_op(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);
    uint8_t f7 = INSTR32_GET_FUNCT7(instr);
    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint8_t rs2 = INSTR32_RS2_GET(instr);

    switch (f7) {
        case FOP_FUNC7_FADD_S:
        case FOP_FUNC7_FSUB_S:
        case FOP_FUNC7_FMUL_S:
        case FOP_FUNC7_FDIV_S:
        case FOP_FUNC7_FSGNJ_S:
        // case FOP_FUNC7_FSGNJN_S:
        // case FOP_FUNC7_FSGNJX_S:
        case FOP_FUNC7_FMIN_S:
        // case FOP_FUNC7_FMAX_S:
        case FOP_FUNC7_FADD_D:
        case FOP_FUNC7_FSUB_D:
        case FOP_FUNC7_FMUL_D:
        case FOP_FUNC7_FDIV_D:
        case FOP_FUNC7_FSGNJ_D:
        // case FOP_FUNC7_FSGNJN_D:
        // case FOP_FUNC7_FSGNJX_D:
        case FOP_FUNC7_FMIN_D:
        // case FOP_FUNC7_FMAX_D:
        {
            target_fplong t1 = shadow_fpregs[rs1];
            target_fplong t2 = shadow_fpregs[rs2];
            propagate_taint32__fp_regop_impl(vcpu_idx, rd, t1, t2);
            break;
        }
        case FOP_FUNC7_FSQRT_S:
        case FOP_FUNC7_FSQRT_D:
        {
            target_fplong t1 = shadow_fpregs[rs1];
            propagate_taint32__fp_sqrt_impl(vcpu_idx, rd, t1);
            break;
        }
        case FOP_FUNC7_FCVT_W_S:
        // case FOP_FUNC7_FCVT_WU_S:
        case FOP_FUNC7_FMV_W_X:
        case FOP_FUNC7_FCVT_W_D:
        case FOP_FUNC7_FCLASS_D:
        // case FOP_FUNC7_FCVT_WU_D:
        {
            target_fplong t1 = shadow_fpregs[rs1];
            propagate_taint32__fp_to_int_impl(vcpu_idx, rd, t1);
            break;
        }
        case FOP_FUNC7_FCVT_S_W:
        // case FOP_FUNC7_FCVT_S_WU:
        case FOP_FUNC7_FCVT_D_W:
        // case FOP_FUNC7_FCVT_D_WU:
        {
            target_ulong t1 = shadow_regs[rs1];
            propagate_taint32__fp_from_int_impl(vcpu_idx, rd, t1);
            break;
        }
        case FOP_FUNC7_FMV_X_W__OR__FCLASS_S:
            // Discriminate between the two instructions that have the same opcode but not the same taint propagation policy.
            switch (f3) {
                case 0b000:
                {
                    // FMV_X_W
                    target_ulong t1 = shadow_regs[rs1];
                    propagate_taint32__fp_from_int_impl(vcpu_idx, rd, t1);
                    break;
                }
                case 0b001:
                {
                    // FCLASS_S
                    target_fplong t1 = shadow_fpregs[rs1];
                    propagate_taint32__fp_to_int_impl(vcpu_idx, rd, t1);
                    break;
                }
                default:
                    fprintf(stderr, "Unknown funct3 for FOP_FUNC7_FMV_X_W__OR__FCLASS_S opcode: 0x%" PRIx32 "\n", instr);
                    break;
            }
            break;
        case FOP_FUNC7_FEQ_S:
        // case FOP_FUNC7_FLT_S:
        // case FOP_FUNC7_FLE_S:
        case FOP_FUNC7_FEQ_D:
        // case FOP_FUNC7_FLT_D:
        // case FOP_FUNC7_FLE_D:
        {
            target_ulong t1 = shadow_fpregs[rs1];
            target_ulong t2 = shadow_fpregs[rs2];
            propagate_taint32__fp_cmp_impl(vcpu_idx, rd, t1, t2);
            break;
        }
        case FOP_FUNC7_FCVT_S_D:
        case FOP_FUNC7_FCVT_D_S:
        {
            target_ulong t1 = shadow_fpregs[rs1];
            propagate_taint32__fp_mv_impl(vcpu_idx, rd, t1);
            break;
        }
        default:
            fprintf(stderr, "Unknown opcode for instr: 0x%" PRIx32 "\n", instr);
            break;
    }
}




static void propagate_taint32_JALR(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1)
{
    // Two actions:
    // - Clears the taint in rd
    shadow_regs[rd] = 0;
    // - Taints the PC if rs is tainted
    target_ulong rs_shadowval = shadow_regs[rs1];

    if (rs_shadowval) {
        taint_pc(vcpu_idx);
    }
}

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
        propagate_taint32__load(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_LOAD_FP:
        propagate_taint32__load_fp(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_MISC_MEM: // FIXME: what is misc mem?
        break;

    case INSTR32_OPCODE_HI_OP_IMM:
        propagate_taint32__reg_imm_op(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_AUIPC:
        propagate_taint32_AUIPC(vcpu_idx, instr);
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
        propagate_taint32_LUI(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_OP_32:
        // FIXME: Support for M extension (MULW, DIVW, ...)
        propagate_taint32__reg_reg_op32(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_FP_MADD:
    case INSTR32_OPCODE_HI_FP_MSUB:
    case INSTR32_OPCODE_HI_FP_NMSUB:
    case INSTR32_OPCODE_HI_FP_NMADD:
        propagate_taint32__fp_madd_msub_nmadd_nmsub(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_FP_OP:  // FIXME: no support for floats (F extension)
        propagate_taint32__fp_op(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_BRANCH:
        propagate_taint32__branch(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_JALR:
        uint8_t rd = INSTR32_RD_GET(instr);
        uint8_t rs1 = INSTR32_RS1_GET(instr);
        propagate_taint32_JALR(vcpu_idx, rd, rs1);
        break;

    case INSTR32_OPCODE_HI_JAL:
        propagate_taint32_JAL(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_SYSTEM:
        // FIXME: no support for CSR instructions
        break;

    default:
        fprintf(stderr, "Unknown opcode for instr: 0x%" PRIx32 "\n", instr);
        break;
    }
}

/***
 * Compressed instructions
 ***/


static void propagate_taint_CADDI4SPN(unsigned int vcpu_idx, uint16_t instr)
{
    uint8_t rdc = INSTR16_CIW_RDC_GET(instr);
    uint8_t rd = REG_OF_COMPRESSED(rdc);

    uint8_t nzuimm_5_4 = (instr >> 11) & MASK(2);
    uint8_t nzuimm_9_6 = (instr >> 7) & MASK(4);
    uint8_t nzuimm_2 = (instr >> 6) & 1;
    uint8_t nzuimm_3 = (instr >> 5) & 1;

    // zero extended non zero immediate
    uint16_t nzuimm =
        (nzuimm_2 << 2) |
        (nzuimm_3 << 3) |
        (nzuimm_5_4 << 4) |
        (nzuimm_9_6 << 6) ;

    #ifndef NDEBUG
    if (nzuimm == 0)
    {
        fprintf(stderr, "ADDI4SPN expects nonzero immediate. Instr = 0x%" PRIx16 "\n", instr);
        exit(1);
    }
    #endif
    // decodes to
    // addi rd, x2, nzuimm
    target_ulong v1 = get_one_reg_value(vcpu_idx, 2);
    target_ulong t1 = shadow_regs[2];

    target_ulong tout = propagate_taint__add(v1, nzuimm, t1, 0);

    shadow_regs[rd] = tout;
}


static void propagate_taint_CLW(unsigned int vcpu_idx, uint16_t instr)
{
    uint8_t rdc = INSTR16_CL_RDC_GET(instr);
    uint8_t rd = REG_OF_COMPRESSED(rdc);

    uint8_t rs1c = INSTR16_CL_RS1C_GET(instr);
    uint8_t rs1 = REG_OF_COMPRESSED(rs1c);


    // zero-extended offset
    uint8_t offset5_3 = (instr >> 10) & MASK(3);
    uint8_t offset2 = (instr >> 6) & 1;
    uint8_t offset6 = (instr >> 5) & 1;
    uint8_t offset =
        (offset2 << 2) |
        (offset5_3 << 3) |
        (offset6 << 6);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);

    propagate_taint_load_impl(vcpu_idx, rd, v1, offset, t1, LOAD_LW);
}

#ifdef TARGET_RISCV64
static void propagate_taint_CLD(unsigned int vcpu_idx, uint16_t instr)
{
    uint8_t rdc = INSTR16_CL_RDC_GET(instr);
    uint8_t rd = REG_OF_COMPRESSED(rdc);

    uint8_t rs1c = INSTR16_CL_RS1C_GET(instr);
    uint8_t rs1 = REG_OF_COMPRESSED(rs1c);


    // zero-extended offset
    uint8_t offset5_3 = (instr >> 10) & MASK(3);
    uint8_t offset7_6 = (instr >> 5) & 2;
    uint8_t offset =
        (offset5_3 << 3) |
        (offset7_6 << 6);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);

    propagate_taint_load_impl(vcpu_idx, rd, v1, offset, t1, LOAD_LD);
}
#endif

static void propagate_taint_CSW(unsigned int vcpu_idx, uint16_t instr)
{
    uint8_t rs1c = INSTR16_CS_RS1C_GET(instr);
    uint8_t rs1 = REG_OF_COMPRESSED(rs1c);

    uint8_t rs2c = INSTR16_CS_RS2C_GET(instr);
    uint8_t rs2 = REG_OF_COMPRESSED(rs2c);


    // zero-extended offset
    uint8_t offset5_3 = (instr >> 10) & MASK(3);
    uint8_t offset2 = (instr >> 6) & 1;
    uint8_t offset6 = (instr >> 5) & 1;
    uint8_t offset =
        (offset2 << 2) |
        (offset5_3 << 3) |
        (offset6 << 6);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];
    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    propagate_taint_store_impl(vcpu_idx, vals.v1, vals.v2, offset, t1, t2, STORE_SW);
}

#ifdef TARGET_RISCV64
static void propagate_taint_CSD(unsigned int vcpu_idx, uint16_t instr)
{
    uint8_t rs1c = INSTR16_CS_RS1C_GET(instr);
    uint8_t rs1 = REG_OF_COMPRESSED(rs1c);

    uint8_t rs2c = INSTR16_CS_RS2C_GET(instr);
    uint8_t rs2 = REG_OF_COMPRESSED(rs2c);


    // zero-extended offset
    uint8_t offset5_3 = (instr >> 10) & MASK(3);
    uint8_t offset7_6 = (instr >> 5) & 2;
    uint8_t offset =
        (offset5_3 << 3) |
        (offset7_6 << 6);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];
    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    propagate_taint_store_impl(vcpu_idx, vals.v1, vals.v2, offset, t1, t2, STORE_SD);
}
#endif

static void propagate_taint_CLI(unsigned int vcpu_idx, uint16_t instr)
{
    // writes immediate to rd (!= x0)
    uint8_t rd = INSTR16_C1_RD_GET(instr);
    assert(rd != 0);
    shadow_regs[rd] = 0;

    _DEBUG("Propagate C.LI(?) -> r%" PRIu8 "\n", rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "\n", rd, 0);


}

static void propagate_taint_CLUI_CADDI16SP(unsigned int vcpu_idx, uint16_t instr)
{
    uint8_t rd = INSTR16_C1_RD_GET(instr);
    // rd == x0 reserved
    assert(rd != 0);

    if (rd == 2)
    {
        // rd == x2 => C.ADDI16SP
        // x2 <- x2 + nzimm

        uint16_t nzimm0_9 =
            0b00000 |
            ((instr >> 6) & 0x1) << 4 |
            ((instr >> 2) & 0x1) << 5 |
            ((instr >> 5) & 0x1) << 6 |
            ((instr >> 3) & 0x11) << 7 |
            ((instr >> 12) & 0x1) << 9
        ;

        assert(nzimm0_9 != 0);

        uint16_t nzimm =SIGN_EXTEND(nzimm0_9, 9);

        target_ulong v1 = get_one_reg_value(vcpu_idx, rd);
        target_ulong t1 = shadow_regs[rd];

        target_ulong tout = propagate_taint__add(v1, nzimm, t1, 0);

        shadow_regs[rd] = tout;

        _DEBUG("Propagate C.ADDI16SP(0x%" PRIxXLEN ") -> r%" PRIu8 "\n", v1,  rd);
        _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rd, t1, rd, tout);

    }
    else
    {
        // else => C.LUI
        shadow_regs[rd] = 0;

        _DEBUG("Propagate C.LUI(?) -> r%" PRIu8 "\n", rd);
        _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " \n", rd, 0);

    }
}

static void propagate_taint_CJ(unsigned int vcpu_idx, uint16_t instr)
{
    // C.J does not propagate any taint architecturally, assuming that the jump offset immediate is not tainted.
}


/* opcode dispatch */
static void propagate_taint16(unsigned int vcpu_idx, uint16_t instr)
{
    // the lsb is NOT 0b11 for all 16b instructions
    uint8_t lo = instr & MASK(2);
    assert(lo != 0b11);

    uint8_t opcode = INSTR16_OPCODE_GET(instr);
    switch (opcode)
    {
    case INSTR16_RV64_OPCODE_ADDI4SPN:
    {
        propagate_taint_CADDI4SPN(vcpu_idx, instr);
        break;
    }
    case INSTR16_RV64_OPCODE_FLD:
    {
        // FIXME: floating point not supported
        break;
    }
    case INSTR16_RV64_OPCODE_LW:
    {
        propagate_taint_CLW(vcpu_idx, instr);
        break;
    }
#ifdef TARGET_RISCV64
    case INSTR16_RV64_OPCODE_LD:
    {
        propagate_taint_CLD(vcpu_idx, instr);
        break;
    }
#endif
    case INSTR16_RV64_OPCODE__RESERVED:
    {
        fprintf(stderr, "Unexpected reserved instr16: 0x%" PRIx16 "\n", instr);
        break;
    }
    case INSTR16_RV64_OPCODE_FSD:
    {
        // FIXME: floating point not supported
        break;
    }
    case INSTR16_RV64_OPCODE_SW:
    {
        propagate_taint_CSW(vcpu_idx, instr);
        break;
    }
#ifdef TARGET_RISCV64
    case INSTR16_RV64_OPCODE_SD:
    {
        propagate_taint_CSD(vcpu_idx, instr);
        break;
    }
#endif
    case INSTR16_RV64_OPCODE_ADDI:
    case INSTR16_RV64_OPCODE_ADDIW:
    {
        // FIXME: not supported
        // can prob have common impl w/ additional param
        _DEBUG("C.ADDI/C.ADD not supported\n");
        break;

    }
    case INSTR16_RV64_OPCODE_LI:
    {
        propagate_taint_CLI(vcpu_idx, instr);
        break;
    }
    case INSTR16_RV64_OPCODE_LUI_ADDI16SP:
    {
        propagate_taint_CLUI_CADDI16SP(vcpu_idx, instr);
        break;
    }
    case INSTR16_RV64_OPCODE_J:
    {
        propagate_taint_CJ(vcpu_idx, instr);
        break;
    }
    case INSTR16_RV64_OPCODE_MISC_ALU:
    case INSTR16_RV64_OPCODE_BEQZ:
    case INSTR16_RV64_OPCODE_BNEZ:
    case INSTR16_RV64_OPCODE_SLLI:
    case INSTR16_RV64_OPCODE_FLDSP:
    case INSTR16_RV64_OPCODE_LWSP:
    case INSTR16_RV64_OPCODE_LDSP:
    case INSTR16_RV64_OPCODE_JALR_MV_ADD:
    case INSTR16_RV64_OPCODE_FSDSP:
    case INSTR16_RV64_OPCODE_SWSP:
    case INSTR16_RV64_OPCODE_SDSP:
    {
        _DEBUG("TODO: compressed instr 0x%" PRIx16 " with opcode: 0x%" PRIx8 "\n", instr, opcode);
        break;
    }
    default:
    {
        fprintf(stderr, "Unknown opcode for instr16: 0x%" PRIx16 "\n", instr);
        break;
    }
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


