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




/****************************
 * Taint propagation logic, per instruction
 ***************************/



/***
 * Loads
 * 
 * FIXME: need to do vaddr->paddr translation. 2 options:
 * 1. Use the official plugin API: translation in mem cb callback
 *      + uses TLB data, so low overhead
 * 2. Use my own API: full PTW so high overhead!
 ***/

enum LOAD_TYPE {
    LOAD_LB, LOAD_LH, LOAD_LW, LOAD_LD,
    LOAD_LBU, LOAD_LHU, LOAD_LWU
};

static void propagate_taint_load_impl(unsigned int vcpu_idx, uint8_t rd, uint64_t v1, uint64_t offt, uint64_t t1, enum LOAD_TYPE lt)
{
    uint64_t vaddr = v1 + offt;

    // Do not read/write to the shadow mem concurrently with a taint-get/set query
    pthread_mutex_lock(&shadow_lock);

    uint64_t tout = 0;
    if (t1)
    {
        // tainted ptr implies fully tainted value!
        tout = -1;
        _DEBUG("Propagate load[v=%" PRIx64 " TAINTED]: t%" PRIu8 " <- " PRIx64 "\n", vaddr, rd, tout);
    }
    else
    {
        // else propagate the taint from the memory location.



        // adress translation
        // FIXME: does this work or shd we also add logic in mem callback?
        qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_idx);
        uint64_t paddr = qemu_plugin_vaddr_to_paddr(cs, vaddr);
        uint64_t ram_addr = 0;

        if (qemu_plugin_paddr_to_ram_addr(paddr, &ram_addr))
        {
            //Non-ram location
            //FIXME: how shd we handle this?
            tout = 0;
            _DEBUG("Propagate load[v=%" PRIx64 ", p=%" PRIx64 "]: [non-RAM] location, t%" PRIu8 " <- %" PRIx64 "\n", vaddr, paddr, rd, tout);
        }
        else
        {

        

            // NOTE: the loaded value is sign (/value for the U variants) extended
            // to XLEN bits before being stored in the register.
            // This means we will update all the bits in the shadow register.

            uint64_t t = 0;

            // Note that casting from short int to large uint does the sign expansion,
            // casting from short uint to large uint does not.

            switch (lt)
            {
                case LOAD_LB:
                    t = *(int8_t*)(shadow_mem + ram_addr);
                    break;
                case LOAD_LH:
                    t = *(int16_t*)(shadow_mem + ram_addr);
                    break;
                case LOAD_LW:
                    t = *(int32_t*)(shadow_mem + ram_addr);
                    break;
                case LOAD_LD:
                    t = *(int64_t*)(shadow_mem + ram_addr);
                    break;
                case LOAD_LBU:
                    t = *(uint8_t*)(shadow_mem + ram_addr);
                    break;
                case LOAD_LHU:
                    t = *(uint16_t*)(shadow_mem + ram_addr);
                    break;
                case LOAD_LWU:
                    t = *(uint32_t*)(shadow_mem + ram_addr);
                    break;
            }

            tout = t;
            _DEBUG("Propagate load[v=%" PRIx64 ", p=%" PRIx64 "]: t%" PRIu8 " <- t[%" PRIx64 "]=" PRIx64 "\n", vaddr, paddr, rd, tout);
        }
    }
    
    shadow_regs[rd] = tout;

    pthread_mutex_unlock(&shadow_lock);
}

static void propagate_taint32__load(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);

    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint16_t imm0_11 = INSTR32_I_IMM_0_11_GET(instr);

    uint64_t t1 = shadow_regs[rs1];
    uint64_t v1 = get_one_reg_value(vcpu_idx, rs1);
    
    // The effective load address is obtained by adding register rs1 to
    // the sign-extended 12-bit offset.
    
    // do the sign extension, interpret as signed
    int64_t imm =  (((int64_t)imm0_11) << 52) >> 52;

    static enum LOAD_TYPE to_load_type[] = {
        [INSTR32_F3_LB] = LOAD_LB,
        [INSTR32_F3_LH] = LOAD_LH,
        [INSTR32_F3_LW] = LOAD_LW,
        [INSTR32_F3_LD] = LOAD_LD,
        [INSTR32_F3_LBU] = LOAD_LBU,
        [INSTR32_F3_LHU] = LOAD_LHU,
        [INSTR32_F3_LWU] = LOAD_LWU,
    };
    enum LOAD_TYPE lt = to_load_type[f3];

    propagate_taint_load_impl(vcpu_idx, rd, v1, imm, t1, lt);
}


/***
 * Stores
 ***/
enum STORE_TYPE {
    STORE_SB, STORE_SH, STORE_SW, STORE_SD
};

static void propagate_taint_store_impl(unsigned int vcpu_idx, uint64_t v1, uint64_t v2, uint64_t offt, uint64_t t1, uint64_t t2, enum STORE_TYPE st)
{

    // Tainted ptr store: need to taint every possible dest
    // ie all combinations of tainted bits (in vaddr, not in t1!)
    // FIXME: support tainted dest.
    if (t1)
    {
        fprintf(stderr, "ERROR: no support for tainted store destinations yet.\n");
    }


    //FIXME: need to have tainted pointer 
    //FIXME: use addi logic to propagate taint!
    uint64_t vaddr = v1 + offt;

    // adress translation
    // FIXME: does this work or shd we also add logic in mem callback?
    qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_idx);
    uint64_t paddr = qemu_plugin_vaddr_to_paddr(cs, vaddr);
    uint64_t ram_addr = 0;
    if (qemu_plugin_paddr_to_ram_addr(paddr, &ram_addr))
    {
        // non-ram location
        _DEBUG("Propagate store[v=%" PRIx64 ", p=%" PRIx64 "]: to [non-RAM] ; t= %" PRIx64 " not written\n", vaddr, paddr, t2);
    }
    else
    {
        // truncate the taint when writing

        // Do not read/write to the shadow mem concurrently with a taint-get/set query
        pthread_mutex_lock(&shadow_lock);


        switch (st)
        {
            case STORE_SB:
                *(uint8_t*)(shadow_mem + ram_addr) = t2;
                break;
            case STORE_SH:
                *(uint16_t*)(shadow_mem + ram_addr) = t2;
                break;
            case STORE_SW:
                *(uint32_t*)(shadow_mem + ram_addr) = t2;
                break;
            case STORE_SD:
                *(uint64_t*)(shadow_mem + ram_addr) = t2;
                break;
        }

        // Do not read/write to the shadow mem concurrently with a taint-get/set query
        pthread_mutex_unlock(&shadow_lock);


        _DEBUG("Propagate store[v=%" PRIx64 ", p=%" PRIx64 "]: t[%" PRIx64 "] = %" PRIx64 "\n", vaddr, paddr, ram_addr, t2);
    }
}

static void propagate_taint32__store(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);

    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint8_t rs2 = INSTR32_RS2_GET(instr);

    // imm0_11 is split in S form, the macro concatenates the two parts
    uint16_t imm0_11 = INSTR32_S_IMM_0_11_GET(instr);


    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];
    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    // The effective address is obtained by adding register rs1 to
    // the sign-extended 12-bit offset.

    // do the sign extension, interpret as signed
    // NOTE: we cd combine the concatenation and sign extension, but really micro-opt
    int64_t imm =  (((int64_t)imm0_11) << 52) >> 52;

    static enum LOAD_TYPE to_store_type[] = {
        [INSTR32_F3_SB] = STORE_SB,
        [INSTR32_F3_SH] = STORE_SH,
        [INSTR32_F3_SW] = STORE_SW,
        [INSTR32_F3_SD] = STORE_SD,
    };
    enum STORE_TYPE st = to_store_type[f3];

    propagate_taint_store_impl(vcpu_idx, vals.v1, vals.v2, imm, t1, t2, st);
}


/***
 * Boolean and arithmetic operations
 **/

static uint64_t propagate_taint_op__lazy(uint64_t t1, uint64_t t2)
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

    // if any bit tainted in any of the operands, the output is completely tainted
    bool is_out_tainted = (t1 || t2);

    uint64_t tout = is_out_tainted ? -1 : 0;

    return tout;
}

// ADD and SUB: need to consider the carry.
//   - approximation: (from Valgrind's memcheck): taint everything to the left
//     of the first tainted carry.
//   - better: carry-by-carry taint propagation


static uint64_t propagate_taint__add(uint64_t v1, uint64_t v2, uint64_t t1, uint64_t t2)
{
    /*
      Taint using the properties of ADD identified in the CellIFT paper.
    */

    uint64_t v1_with_ones = v1 | t1;
    uint64_t v2_with_ones = v2 | t2;

    uint64_t v1_with_zeros = v1 & (~t1);
    uint64_t v2_with_zeros = v2 & (~t2);

    // Taint:
    // 1. taint directly from input bit to the corresponding output bit
    // 2. taint from carries

    uint64_t sum_with_ones = v1_with_ones + v2_with_ones;
    uint64_t sum_with_zeros = v1_with_zeros + v2_with_zeros;

    uint64_t tout = t1 | t2 | (sum_with_ones ^ sum_with_zeros);

    return tout;
}


static void propagate_taint_ADD(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    uint64_t tout = propagate_taint__add(vals.v1, vals.v2, t1, t2);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate ADD(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);

}

static void propagate_taint_ADDI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // Acceptable precision is important bc "mov rd,rs" is just an alias for "addi rd,rs,0"
    uint64_t v1 = get_one_reg_value(vcpu_idx, rs1);
    uint64_t imm = (((int64_t)imm0_11) << 52) >> 52;
    
    _DEBUG("Propagate ADDI(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", v1, imm, rd);

    uint64_t t1 = shadow_regs[rs1];

    uint64_t tout = propagate_taint__add(v1, imm, t1, 0);

    shadow_regs[rd] = tout;

    _DEBUG("t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rd, tout);


}


static void propagate_taint_SUB(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);
    
    uint64_t v1_with_ones = vals.v1 | t1;
    uint64_t v2_with_ones = vals.v2 | t2;

    uint64_t v1_with_zeros = vals.v1 & (~t1);
    uint64_t v2_with_zeros = vals.v2 & (~t2);

    // Taint:
    // 1. taint directly from input bit to the corresponding output bit
    // 2. taint from carries

    uint64_t diff_zero_ones = v1_with_zeros - v2_with_ones;
    uint64_t diff_ones_zeros = v1_with_ones - v2_with_zeros;

    uint64_t tout = t1 | t2 | (diff_zero_ones ^ diff_ones_zeros);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SUB(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);
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

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    uint64_t tA = (~t1) & vals.v1 & t2;
    uint64_t tB = t1 & (~t2) & vals.v2;
    uint64_t tC = t1 & t2;
    uint64_t tout = tA | tB | tC;

    shadow_regs[rd] = tout;

    _DEBUG("Propagate AND(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);


}

static void propagate_taint_ANDI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    uint64_t imm = (((int64_t)imm0_11) << (64 - 12)) >> (64 - 12);
    
    uint64_t v1 = get_one_reg_value(vcpu_idx, rs1);
    uint64_t t1 = shadow_regs[rs1];

    /*
     * With T2 = 0, the taint propagation simplifies to
     * AND: (T1 * V2)
     */

    uint64_t tout = t1 & imm;
    shadow_regs[rd] = tout;

    _DEBUG("Propagate ANDI(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", v1, imm, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rd, tout);


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

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    uint64_t tA = (~t1) & (~vals.v1) & t2;
    uint64_t tB = t1 & (~t2) & (~vals.v2);
    uint64_t tC = t1 & t2;
    uint64_t tout = tA | tB | tC;

    shadow_regs[rd] = tout;

    _DEBUG("Propagate OR(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);

}


static void propagate_taint_ORI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    uint64_t imm = (((int64_t)imm0_11) << (64 - 12)) >> (64 - 12);
    
    uint64_t v1 = get_one_reg_value(vcpu_idx, rs1);
    uint64_t t1 = shadow_regs[rs1];

    /*
     * With T2 = 0, the taint propagation simplifies to
     * OR: (T1 * (NOT V2))
     */

    uint64_t tout = t1 & (~imm);
    shadow_regs[rd] = tout;


    _DEBUG("Propagate ORI(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", v1, imm, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rd, tout);

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
    uint64_t t1, t2;
    if (rs1 == rs2)
    {
        tout = 0;
    }
    else
    {
        t1 = shadow_regs[rs1];
        t2 = shadow_regs[rs2];

        tout = t1 | t2;
    }

    shadow_regs[rd] = tout;

    _DEBUG("Propagate XOR(X, X) -> r%" PRIu8 "\n", rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);


}


static void propagate_taint_XORI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    /*
     * XOR: union of the taints.
     */

    uint64_t t1 = shadow_regs[rs1];
    uint64_t tout = t1;
    shadow_regs[rd] = t1;

    _DEBUG("Propagate XORI(X, X) -> r%" PRIu8 "\n", rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rd, tout);


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

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

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

    _DEBUG("Propagate SLL(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);

}

static void propagate_taint_SLLI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t shamt)
{
    uint64_t v1 = get_one_reg_value(vcpu_idx, rs1);
    uint64_t t1 = shadow_regs[rs1];

    uint64_t tout = t1 << shamt;

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLLI(%" PRIx64 ", shamt=%" PRIu8 ") -> r%" PRIu8 "\n", v1, shamt, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rd, tout);

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

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

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

    _DEBUG("Propagate SRL(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);

}


static void propagate_taint_SRLI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t shamt)
{
    uint64_t v1 = get_one_reg_value(vcpu_idx, rs1);
    uint64_t t1 = shadow_regs[rs1]; 

    uint64_t tout = t1 >> shamt;
    
    shadow_regs[rd] = tout;

    _DEBUG("Propagate SRLI(%" PRIx64 ", shamt=%" PRIu8 ") -> r%" PRIu8 "\n", v1, shamt, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rd, tout);

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

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

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

    _DEBUG("Propagate SRA(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);

}

static void propagate_taint_SRAI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t shamt)
{
    uint64_t v1 = get_one_reg_value(vcpu_idx, rs1);
    uint64_t t1 = shadow_regs[rs1]; 

    uint64_t tout = ((int64_t)t1) >> shamt;
    
    shadow_regs[rd] = tout;

    _DEBUG("Propagate SRAI(%" PRIx64 ", shamt=%" PRIu8 ") -> r%" PRIu8 "\n", v1, shamt, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rd, tout);


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

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);
    uint64_t tout = taint_result__sltu(vals.v1, vals.v2, t1, t2);
    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLTU(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);

}

static void propagate_taint_SLTIU(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    uint64_t imm = (((int64_t)imm0_11) << (64 - 12)) >> (64 - 12);

    uint64_t t1 = shadow_regs[rs1];

    uint64_t v1 = get_one_reg_value(vcpu_idx, rs1);
    uint64_t tout = taint_result__sltu(v1, imm, t1, 0);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLTIU(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", v1, imm, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rd, tout);


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

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);
    uint64_t tout = taint_result__slt(vals.v1, vals.v2, t1, t2);
    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLT(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);

}

static void propagate_taint_SLTI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    uint64_t imm = (((int64_t)imm0_11) << (64 - 12)) >> (64 - 12);

    uint64_t t1 = shadow_regs[rs1];

    uint64_t v1 = get_one_reg_value(vcpu_idx, rs1);
    uint64_t tout = taint_result__slt(v1, imm, t1, 0);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLTIU(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", v1, imm, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rd, tout);
}


// AUIPC and LUI


static void propagate_taint32_AUIPC(unsigned int vcpu_idx, uint32_t instr)
{
    uint32_t imm31_12 = INSTR32_U_IMM_12_31_GET(instr);
    uint8_t rd = INSTR32_RD_GET(instr);

    // In RV64:
    // AUIPC appends 12 low-order zero bits to the 20-bit
    // U-immediate, sign-extends the result to 64 bits,
    // adds it to the address of the AUIPC instruction (pc),
    // then places the result in register rd.
    uint32_t imm32 = imm31_12 << 12;

    // do the sign extension, interpret as signed
    int64_t imm = (((int64_t)imm32) << 32) >> 32;

    //FIXME: need an additionnal API to get pc!
    //FIXME: use the add propagation logic to propagate pc taint to rd
    //FIXME: for now assume pc not tainted

    uint64_t tout = 0;
    shadow_regs[rd] = tout;


    shadow_regs[rd] = tout;

    _DEBUG("Propagate AUIPC(%" PRIx64 ") -> r%" PRIu8 "\n", imm, rd);
    _DEBUG(" -> t%" PRIu8 " = %" PRIx64 "\n", rd, tout);
}

static void propagate_taint32_LUI(unsigned int vcpu_idx, uint32_t instr)
{
    uint32_t imm31_12 = INSTR32_U_IMM_12_31_GET(instr);
    uint8_t rd = INSTR32_RD_GET(instr);

    // In RV64:
    // LUI places the 20-bit U-immediate
    // into bits 31–12 of register rd and places zero in the lowest 12 bits.
    // The 32-bit result is sign-extended to 64 bits.
    
    // Taint-wise: clears rd!
    
    uint32_t imm32 = imm31_12 << 12;
    int64_t imm = (((int64_t)imm32) << 32) >> 32;

    uint64_t tout = 0;
    shadow_regs[rd] = tout;

    _DEBUG("Propagate LUI(%" PRIx64 ") -> r%" PRIu8 "\n", imm, rd);
    _DEBUG(" -> t%" PRIu8 " = %" PRIx64 "\n", rd, tout);

}


/***
 * M extension
 ***/

static void propagate_taint_MUL(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    uint64_t tout = propagate_taint_op__lazy(t1, t2);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate MUL(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);
}

static void propagate_taint_MULH(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    uint64_t tout = propagate_taint_op__lazy(t1, t2);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate MULH(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);
}

static void propagate_taint_MULHSU(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    uint64_t tout = propagate_taint_op__lazy(t1, t2);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate MULHSU(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);
}

static void propagate_taint_MULHU(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    uint64_t tout = propagate_taint_op__lazy(t1, t2);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate MULHU(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);
}

static void propagate_taint_DIV(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    uint64_t tout = propagate_taint_op__lazy(t1, t2);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate DIV(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);
}

static void propagate_taint_DIVU(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    uint64_t tout = propagate_taint_op__lazy(t1, t2);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate DIVU(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);
}

static void propagate_taint_REM(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    uint64_t tout = propagate_taint_op__lazy(t1, t2);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate REM(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);
}

static void propagate_taint_REMU(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    uint64_t tout = propagate_taint_op__lazy(t1, t2);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate REMU(%" PRIx64 ",%" PRIx64 ") -> r%" PRIu8 "\n", vals.v1, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = %" PRIx64 "  t%" PRIu8 " = %" PRIx64 " -> t%" PRIu8 " = %" PRIx64 "\n", rs1, t1, rs2, t2, rd, tout);
}

/***
 * Opcode dispatch (uncompressed instructions)
 ***/

static void propagate_taint32__reg_imm_op(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);

    // imm and f7/shamt bits overlap, only one should be used!
    uint16_t imm = INSTR32_I_IMM_0_11_GET(instr);
    uint32_t f7 = INSTR32_GET_FUNCT7(instr);
    // note that shamt is NOT sign extended ()
    uint8_t shamt = INSTR32_I_SHAMT_GET(instr); 
    
    
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
            uint32_t f6 = f7 >> 1;
            if (f6 == INSTR32_F6_SLLI)
            {
                propagate_taint_SLLI(vcpu_idx, rd, rs1, shamt);
            }
            else
            {
                fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLLI: %" PRIx32 "\n", instr);
            }
            break;
        }
        case INSTR32_F3_SRLI__SRAI:
        {
            uint32_t f6 = f7 >> 1;
            if (f6 == INSTR32_F6_SRLI)
            {
                propagate_taint_SRLI(vcpu_idx, rd, rs1, shamt);
            }
            else if (f6 == INSTR32_F6_SRAI)
            {
                propagate_taint_SRAI(vcpu_idx, rd, rs1, shamt);
            }
            else
            {
                fprintf(stderr, "Malformed instruction, unknown f7 for f3=SRLI_SRAI: %" PRIx32 "\n", instr);
            }
            
            break;
        }
        default:
        {
            fprintf(stderr, "Unknown reg-imm op f3 for instr: %" PRIx32 "\n", instr);
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
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=ADD_SUB_MUL: %" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_SLL_MULH:
    {
        if (f7 == INSTR32_F7_SLL)
            propagate_taint_SLL(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_MULH)
            propagate_taint_MULH(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLL_MULH: %" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_SLT_MULHSU:
    {
        if (f7 == INSTR32_F7_SLT)
            propagate_taint_SLT(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_MULHSU)
            propagate_taint_MULHSU(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLT_MULHSU: %" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_SLTU_MULHU:
    {
        if (f7 == INSTR32_F7_SLTU)
            propagate_taint_SLTU(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_MULHU)
            propagate_taint_MULHU(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLTU_MULHU: %" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_XOR_DIV:
    {
        if (f7 == INSTR32_F7_XOR)
            propagate_taint_XOR(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_DIV)
            propagate_taint_DIV(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=XOR_DIV: %" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_SRL_SRA_DIVU:
    {
        if (f7 == INSTR32_F7_SRL)
            propagate_taint_SRL(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_SRA)
            propagate_taint_SRA(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_DIVU)
            propagate_taint_DIVU(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=SRL_SRA_DIVU: %" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_OR_REM:
    {
        if (f7 == INSTR32_F7_OR)
            propagate_taint_OR(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_REM)
            propagate_taint_REM(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=OR_REM: %" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_AND_REMU:
    {
        if (f7 == INSTR32_F7_AND)
            propagate_taint_AND(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_REMU)
            propagate_taint_REMU(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=OR_REM: %" PRIx32 "\n", instr);
        break;
    }
    default:
        fprintf(stderr, "Unknown reg-reg op f3 for instr: %" PRIx32 "\n", instr);
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


    // the opcode always ends with 0b11, dispatch on the higher bits
    // to make it easier for the compiler to create a jump table.
    switch (opcode_hi)
    {
    case INSTR32_OPCODE_HI_LOAD:
        propagate_taint32__load(vcpu_idx, instr);
        break;
    
    case INSTR32_OPCODE_HI_LOAD_FP: // FIXME: no support for floats yet
    case INSTR32_OPCODE_HI_MISC_MEM: // FIXME: what is misc mem?
        break;

    case INSTR32_OPCODE_HI_OP_IMM:
        propagate_taint32__reg_imm_op(vcpu_idx, instr);
        break;
    
    case INSTR32_OPCODE_HI_AUIPC:
        //FIXME: AUIPC does not read pc taint!
        propagate_taint32_AUIPC(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_OP_IMM_32:
        //FIXME: wordsize regimm ops in RV64
        //       -> sign extended so easy to implement on top of dw size
        break;
    
    case INSTR32_OPCODE_HI_STORE:
        propagate_taint32__store(vcpu_idx, instr);
        break;

    case INSTR32_OPCODE_HI_STORE_FP: // FIXME: no support for floats (F extension)
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
        //FIXME: wordsize reg reg ops in RV64
        // don't forget M extension (MULW, DIVW, ...)
        //       -> sign extended so easy to implement on top of dw size
        break;

    case INSTR32_OPCODE_HI_MADD:
    case INSTR32_OPCODE_HI_MSUB:
    case INSTR32_OPCODE_HI_NMSUB:
    case INSTR32_OPCODE_HI_NMADD:
    case INSTR32_OPCODE_HI_OP_FP:  // FIXME: no support for floats (F extension)
        break;

    case INSTR32_OPCODE_HI_BRANCH:
        // no control flow taint
        break;
    
    case INSTR32_OPCODE_HI_JALR:
    case INSTR32_OPCODE_HI_JAL:
        // no control flow taint BUT
        // - need to clear taint in rd
        // - need to taint to pc if reg input is tainted
        // FIXME: clear rd taint
        break;

    case INSTR32_OPCODE_HI_SYSTEM:
        // FIXME: no support for CSR instructions
        break;

    default:
        fprintf(stderr, "Unknown opcode for instr: %" PRIx32 "\n", instr);
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
        fprintf(stderr, "ADDI4SPN expects nonzero immediate. Instr = %" PRIx16 "\n", instr);
        exit(1);
    }
    #endif
    // decodes to
    // addi rd, x2, nzuimm
    uint64_t v1 = get_one_reg_value(vcpu_idx, 2);
    uint64_t t1 = shadow_regs[2];

    uint64_t tout = propagate_taint__add(v1, nzuimm, t1, 0);
    
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

    uint64_t t1 = shadow_regs[rs1];
    uint64_t v1 = get_one_reg_value(vcpu_idx, rs1);

    propagate_taint_load_impl(vcpu_idx, rd, v1, offset, t1, LOAD_LW);
}

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

    uint64_t t1 = shadow_regs[rs1];
    uint64_t v1 = get_one_reg_value(vcpu_idx, rs1);

    propagate_taint_load_impl(vcpu_idx, rd, v1, offset, t1, LOAD_LD);
}

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

    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];
    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    propagate_taint_store_impl(vcpu_idx, vals.v1, vals.v2, offset, t1, t2, STORE_SW);
}

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

    uint64_t t1 = shadow_regs[rs1];
    uint64_t t2 = shadow_regs[rs2];
    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    propagate_taint_store_impl(vcpu_idx, vals.v1, vals.v2, offset, t1, t2, STORE_SD);
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
    case INSTR16_RV64_OPCODE_LD:
    {
        propagate_taint_CLD(vcpu_idx, instr);
        break;
    }
    case INSTR16_RV64_OPCODE__RESERVED:
    {
        fprintf(stderr, "Unexpected reserved instr16: %" PRIx16 "\n", instr);
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
    case INSTR16_RV64_OPCODE_SD:
    {
        propagate_taint_CSD(vcpu_idx, instr);
        break;
    }
    case INSTR16_RV64_OPCODE_ADDI:
    case INSTR16_RV64_OPCODE_ADDIW:
    {
        // FIXME: not supported
        // can prob have common impl w/ additional param
        fprintf(stderr, "CADDI/CADD not supported\n");
        break;

    }
    case INSTR16_RV64_OPCODE_LI:
    case INSTR16_RV64_OPCODE_LUI_ADDI16SP:
    case INSTR16_RV64_OPCODE_MISC_ALU:
    case INSTR16_RV64_OPCODE_J:
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
        fprintf(stderr, "Unsupported compressed operation: %" PRIx8 "\n", opcode);
        break;
    }
    default:
    {
        fprintf(stderr, "Unknown opcode for instr16: %" PRIx16 "\n", instr);
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
        fprintf(stderr, "ERROR: Unexpected instruction size %" PRIu32 "B for instr: %" PRIx32 "\n", instr_size, instr);
        exit(1);
        break;
    }
}


