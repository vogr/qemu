#include "propagate.h"

#include <qemu-plugin.h>


#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "regs.h"
#include "riscv.h"
#include "params.h"



// Map compressed representation r' (3 bits) to full register repr (5 bits)
// see https://en.wikichip.org/wiki/risc-v/registers
#define REG_OF_COMPRESSED(x) ((uint8_t)x + 8)



/****************************
 * Taint propagation logic, per instruction
 ***************************/



/***
 * Loads
 * 
 * FIXME: In the load instr we have access to the virt address, but the
 *        virt->phys translation can only be done 
 ***/

static void propagate_taint32__load(unsigned int vcpu_idx, uint32_t instr)
{
    uint32_t f3 = instr & INSTR32_FUNCT3_MASK;

    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint16_t imm = INSTR32_I_IMM_0_11_GET(instr);

}


/***
 * Stores
 ***/

static void propagate_taint32__store(unsigned int vcpu_idx, uint32_t instr)
{
    uint32_t f3 = instr & INSTR32_FUNCT3_MASK;

    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint8_t rs2 = INSTR32_RS2_GET(instr);

    uint16_t imm = INSTR32_S_IMM_0_11_GET(instr);
    
}


/***
 * Boolean and arithmetic operations
 **/

static void propagate_taint_op__lazy(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    /*
     * "Lazy" as defined in Valgrind's memcheck:
     *
     * > Lazy. The V bits of all inputs to the operation are pessimistically
     * > summarised into a single bit, using chains of UifU and/or PCastX0
     * > operations. The resulting bit will indicate ``undefined'' if any part
     * > of any input is undefined. This bit is duplicated (using PCast0X) so as
     * > to give suitable shadow output word(s) for the operation.
     *
     *      https://www.usenix.org/legacy/publications/library/proceedings/usenix05/tech/general/full_papers/seward/seward_html/usenix2005.html
     *
     * In essence: reduce each operands taint to a single taint bit, then the output
     * it the AND of these bits, extended to the size of the output.
     *
     * NOTE: assumes that the operation writes to all the bits of rd.
     */

    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    // if any bit tainted in any of the operands, the output is completely tainted
    uint8_t is_out_tainted = t1 || t2;

    uint64_t tout = is_out_tainted ? -1 : 0;

    shadow_regs[rd] = tout;
}

// ADD and SUB: need to consider the carry.
//   - approximation: (from Valgrind's memcheck): taint everything to the left
//     of the first tainted carry.
//   - better: carry-by-carry taint propagation

static void propagate_taint_ADD(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    // FIXME: proper add handling!
    propagate_taint_op__lazy(vcpu_idx, rd, rs1, rs2);
}

static void propagate_taint_SUB(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    // FIXME: proper sub handling!
    propagate_taint_op__lazy(vcpu_idx, rd, rs1, rs2);
}

// AND and OR

static void propagate_taint_AND(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    /* Rule from DECAF (tcg_taint.c)

      Bitwise AND rules:
        Taint1 Value1 Op  Taint2 Value2  ResultingTaint
        0      1      AND 1      X       1
        1      X      AND 0      1       1
        1      X      AND 1      X       1
        ... otherwise, ResultingTaint = 0
        AND: ((NOT T1) * V1 * T2) + (T1 * (NOT T2) * V2) + (T1 * T2)
      */

    assert(rd != 0);

    struct src_regs_values vals = get_src_reg_values(rs1, rs2);

    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    uint64_t tA = (~t1) & vals.v1 & t2;
    uint64_t tB = t1 & (~t2) & vals.v2;
    uint64_t tC = t1 & t2;
    uint64_t tout = tA | tB | tC;

    shadow_regs[rd] = tout;
}

static void propagate_taint_ANDI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    uint64_t vimm = (((int64_t)imm) << (64 - 12)) >> (64 - 12);
    
    uint64_t v1 = get_one_reg_value(rs1);
    uint64_t t1 = shadow_regs[rs1];

    /*
     * With T2 = 0, the taint propagation simplifies to
     * AND: (T1 * V2)
     */

    uint64_t tout = t1 & vimm;
    shadow_regs[rd] = tout;
}

static void propagate_taint_OR(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    /* Rule from DECAF (tcg_taint.c)


      Bitwise OR rules:
        Taint1 Value1 Op  Taint2 Value2  ResultingTaint
        0      0      OR  1      X       1
        1      X      OR  0      0       1
        1      X      OR  1      X       1
        ... otherwise, ResultingTaint = 0
        OR: ((NOT T1) * (NOT V1) * T2) + (T1 * (NOT T2) * (NOT V2)) + (T1 * T2)
      */

    assert(rd != 0);

    struct src_regs_values vals = get_src_reg_values(rs1, rs2);

    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    uint64_t tA = (~t1) & (~vals.v1) & t2;
    uint64_t tB = t1 & (~t2) & (~vals.v2);
    uint64_t tC = t1 & t2;
    uint64_t tout = tA | tB | tC;

    shadow_regs[rd] = tout;
}


static void propagate_taint_ORI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    uint64_t vimm = (((int64_t)imm) << (64 - 12)) >> (64 - 12);
    
    uint64_t v1 = get_one_reg_value(rs1);
    uint64_t t1 = shadow_regs[rs1];

    /*
     * With T2 = 0, the taint propagation simplifies to
     * OR: (T1 * (NOT V2))
     */

    uint64_t tout = t1 & (~vimm);
    shadow_regs[rd] = tout;
}


// XOR

static void propagate_taint_XOR(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    /*
     * XOR: union of the taints.
     *
     * Exception: if rs1 is rs2, then the output is always 0.
     */

    uint64_t tout;
    if (rs1 == rs2)
    {
        tout = 0;
    }
    else
    {
        uint64_t t1 = shadow_regs[rs1];
        uint64_t t2 = shadow_regs[rs2];

        tout = t1 | t2;
    }

    shadow_regs[rd] = tout;
}


static void propagate_taint_XORI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm)
{
    /*
     * XOR: union of the taints.
     */

    uint64_t t1 = shadow_regs[rs1];
    shadow_regs[rd] = t1;
}


// SLL, SRL, SRA

static void propagate_taint_SLL(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    /*
     * Shift left
     * rd <- (uint)rs1 << rs2
     *
     * SLL, SRL, and SRA perform logical left, logical right, and arithmetic right shifts on the value in
     * register rs1 by the shift amount held in the lower 5 bits of register rs2.
     */

    struct src_regs_values vals = get_src_reg_values(rs1, rs2);

    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    /*
     * t1 => left shift the tainted bits (by the 5 lsb of rs2)
     * t2 => if rs1 != 0, everything is tainted
     */

    uint8_t shift = vals.v2 & MASK(5);
    uint8_t t_shift = t2 & MASK(5);

    uint64_t tA = t1 << shift;
    uint64_t tB = (t_shift && (vals.v1 != 0)) ? -1 : 0;

    uint64_t tout = tA | tB;

    shadow_regs[rd] = tout;
}

static void propagate_taint_SRL(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    /*
     * Shift right
     * rd <- (uint)rs1 >> rs2
     *
     * SLL, SRL, and SRA perform logical left, logical right, and arithmetic right shifts on the value in
     * register rs1 by the shift amount held in the lower 5 bits of register rs2.
     */

    struct src_regs_values vals = get_src_reg_values(rs1, rs2);

    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    /*
     * t1 => right shift the tainted bits (by the 5 lsb of rs2)
     * t2 => if rs1 != 0, everything is tainted
     */

    uint8_t shift = vals.v2 & MASK(5);
    uint8_t t_shift = t2 & MASK(5);

    uint64_t tA = t1 >> shift;
    uint64_t tB = (t_shift && (vals.v1 != 0)) ? -1 : 0;

    uint64_t tout = tA | tB;

    shadow_regs[rd] = tout;
}

static void propagate_taint_SRA(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    /*
     * Arithmetic right shift
     * rd <- (int)rs1 >> rs2
     *
     * SLL, SRL, and SRA perform logical left, logical right, and arithmetic right shifts on the value in
     * register rs1 by the shift amount held in the lower 5 bits of register rs2.
     */

    struct src_regs_values vals = get_src_reg_values(rs1, rs2);

    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    /*
     * t1 => right shift the tainted bits (by the 5 lsb of rs2)
     *       since the MSB is replicated by the shift, we also want to
     *       propagate the taint of the MSB during the shift => arithmetic shift
     * t2 => if rs1 != 0 AND rs1 != 0x11..1, everything is tainted
     */

    uint8_t shift = vals.v2 & MASK(5);
    uint8_t t_shift = t2 & MASK(5);

    uint64_t tA = ((int64_t)t1) >> shift;
    uint64_t tB = (t_shift && (vals.v1 != 0) && (vals.v1 != -1)) ? -1 : 0;

    uint64_t tout = tA | tB;

    shadow_regs[rd] = tout;
}

// SLT and SLTU

/*
 * > SLT and SLTU perform signed and unsigned compares respectively, writing
 *   1 to rd if rs1 < rs2.
 * 
 * The taint output is 0 iff inverting the value of a tainted bit cannot change the order
 * of the comparison. Looking at the two cases (unsigned case):
 * 
 * (forall flips of tainted bits, rs1 with flips < rs2 with flips) iff (max({rs1 with flips}) < min({rs2 with flips})
 *          iff (rs1 with with tainted bits set to 1) < (rs2 with tainted bits set to 0)
 * 
 * (forall flips of tainted bits, rs1 with flips >= rs2 with flips) iff (min({rs1 with flips}) >= max({rs2 with flips})
 *          iff (rs1 with with tainted bits set to 0) >= (rs2 with tainted bits set to 1)
 *
 * For the signed case, the sign bit needs to be taken care of individually: if it is tainted, it is set to
 * 0 in the max, and to 1 in the min.
 * 
 * 
 * In the tainted case, only the lsb of rd is tainted.
 *
 * 
 * We reuse the same logic for SLTI/SLTIU
 * 
 * > SLTI (set less than immediate) places the value 1 in register rd if register rs1 is less than the sign-
 * extended immediate when both are treated as signed numbers, else 0 is written to rd. SLTIU is
 * similar but compares the values as unsigned numbers (i.e., the immediate is first sign-extended to
 * XLEN bits then treated as an unsigned numbe
 *
 *
 */

// logic used for SLTU and SLTIU
static uint64_t taint_result__sltu(uint64_t v1, uint64_t v2, uint64_t t1, uint64_t t2)
{
    uint64_t v1_with_ones =  v1 | t1;
    uint64_t v2_with_ones =  v2 | t2;

    uint64_t v1_with_zeros =  v1 & (~t1);
    uint64_t v2_with_zeros =  v2 & (~t2);

    uint8_t stable_compare1 = v1_with_ones < v2_with_zeros;
    uint8_t stable_compare2 = v1_with_zeros >= v2_with_ones;

    uint8_t stable_compare = stable_compare1 | stable_compare2;

    return (! stable_compare);
}

static void propagate_taint_SLTU(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(rs1, rs2);
    shadow_regs[rd] = taint_result__sltu(vals.v1, vals.v2, t1, t2);
}

static void propagate_taint_SLTUI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    uint64_t vimm = (((int64_t)imm) << (64 - 12)) >> (64 - 12);

    uint64_t t1 = shadow_regs[rs1];

    uint64_t v1 = get_one_reg_value(rs1);
    shadow_regs[rd] = taint_result__sltu(v1, vimm, t1, 0);
}

// logic used for SLT and SLTI
static uint64_t taint_result__slt(uint64_t v1, uint64_t v2, uint64_t t1, uint64_t t2)
{
    uint64_t v1_with_ones =  v1 | t1;
    uint64_t v2_with_ones =  v2 | t2;

    uint64_t v1_with_zeros =  v1 & (~t1);
    uint64_t v2_with_zeros =  v2 & (~t2);

    // Swap the sign bit between the "with ones" and "with zeros" to get the
    // max and min values
    // (max is all 1s, except for sign bit ; min is all 0s, except for sign bit)
    // and cast to int to get a signed comparison
    int64_t v1_max = (v1_with_zeros & (~MASK(63))) | (v1_with_ones & MASK(63));
    int64_t v2_max = (v2_with_zeros & (~MASK(63))) | (v2_with_ones & MASK(63));

    int64_t v1_min = (v1_with_ones & (~MASK(63))) | (v1_with_zeros & MASK(63));
    int64_t v2_min = (v2_with_ones & (~MASK(63))) | (v2_with_zeros & MASK(63));

    uint8_t stable_compare1 = v1_max < v2_min;
    uint8_t stable_compare2 = v1_min >= v2_max;

    uint8_t stable_compare = stable_compare1 | stable_compare2;

    return (! stable_compare);

}

static void propagate_taint_SLT(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(rs1, rs2);
    shadow_regs[rd] = taint_result__slt(vals.v1, vals.v2, t1, t2);
}

static void propagate_taint_SLTI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    uint64_t vimm = (((int64_t)imm) << (64 - 12)) >> (64 - 12);

    uint64_t t1 = shadow_regs[rs1];

    uint64_t v1 = get_one_reg_value(rs1);
    shadow_regs[rd] = taint_result__slt(v1, vimm, t1, 0);
}


static void propagate_taint32__reg_imm_op(unsigned int vcpu_idx, uint32_t instr)
{
    uint32_t f3 = instr & INSTR32_FUNCT3_MASK;

    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint16_t imm = INSTR32_I_IMM_0_11_GET(instr);

    if (rd == 0)
    {
        // x0 cannot be tainted
        return;
    }

}



static void propagate_taint32__reg_reg_op(unsigned int vcpu_idx, uint32_t instr)
{
    uint32_t f7_f3 = instr & (INSTR32_FUNCT3_MASK | INSTR32_FUNCT7_MASK);

    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint8_t rs2 = INSTR32_RS2_GET(instr);

    struct src_regs_values vmon = get_src_reg_values(rs1, rs2);
    struct src_regs_values vqemu = get_src_reg_values_qemu(vcpu_idx, rs1, rs2);
    printf("%" PRIx32 "MON op(%" PRIx64 ", %" PRIx64 ")\n", instr, vmon.v1, vmon.v2);
    printf("%" PRIx32 "REG op(%" PRIx64 ", %" PRIx64 ")\n", instr, vqemu.v1, vqemu.v2);

    if (rd == 0)
    {
        // x0 cannot be tainted
        return;
    }

    switch (f7_f3)
    {
    case INSTR32_F3F7_ADD:
    {
        propagate_taint_ADD(vcpu_idx, rd, rs1, rs2);
        break;
    }
    case INSTR32_F3F7_SUB:
    {
        propagate_taint_SUB(vcpu_idx, rd, rs1, rs2);
        break;
    }
    case INSTR32_F3F7_SLL:
    {
        propagate_taint_SLL(vcpu_idx, rd, rs1, rs2);
        break;
    }
    case INSTR32_F3F7_SLT:
    {
        propagate_taint_SLT(vcpu_idx, rd, rs1, rs2);
        break;
    }
    case INSTR32_F3F7_SLTU:
    {
        propagate_taint_SLTU(vcpu_idx, rd, rs1, rs2);
        break;
    }
    case INSTR32_F3F7_XOR:
    {
        propagate_taint_XOR(vcpu_idx, rd, rs1, rs2);
        break;
    }
    case INSTR32_F3F7_SRL:
    {
        propagate_taint_SRL(vcpu_idx, rd, rs1, rs2);
        break;
    }
    case INSTR32_F3F7_SRA:
    {
        propagate_taint_SRA(vcpu_idx, rd, rs1, rs2);
        break;
    }
    case INSTR32_F3F7_OR:
    {
        propagate_taint_OR(vcpu_idx, rd, rs1, rs2);
        break;
    }
    case INSTR32_F3F7_AND:
    {
        propagate_taint_AND(vcpu_idx, rd, rs1, rs2);
        break;
    }
    default:
        break;
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


    // the opcode
    switch (opcode_hi)
    {
    case INSTR32_OPCODE_HI_LOAD:
        propagate_taint32__load(vcpu_idx, instr);
        break;
    case INSTR32_OPCODE_HI_STORE:
        propagate_taint32__store(vcpu_idx, instr);
        break;
    case INSTR32_OPCODE_HI_OP:
        propagate_taint32__reg_reg_op(vcpu_idx, instr);
        break;
    default:
        break;
    }
}


static void propagate_taint16(unsigned int vcpu_idx, uint32_t instr)
{
    // the lsb is NOT 0b11 for all 16b instructions
    uint8_t lo = instr & 0b11;
    assert(lo != 0b11);

    uint16_t f6_f2_op = instr & (INSTR16_FUNCT6_MASK | INSTR16_FUNCT2_MASK | INSTR16_OP_MASK);
    switch (f6_f2_op)
    {
    case INSTR16_OPF2F6_CAND:
    {

        break;
    }
    default:
    {
        break;
    }
    }
}

void propagate_taint(unsigned int vcpu_idx, uint32_t instr_size, uint32_t instr)
{
    switch (instr_size)
    {
    case 16:
        propagate_taint16(vcpu_idx, instr);
        break;
    case 32:
        propagate_taint32(vcpu_idx, instr);
        break;
    default:
        fprintf(stderr, "ERROR: Unexpected instruction size: %" PRIu32 "B.\n", instr_size);
        exit(1);
        break;
    }
}


