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

// NOTE: Floating-point arithmetic tainting is conserative, for example FMADD (r1 x r2) + r3 will be tainted completely if any of the input registers is tainted.

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
    LOAD_LB, LOAD_LH, LOAD_LW,
    LOAD_LBU, LOAD_LHU,
    LOAD_LD, LOAD_LWU,
};

static void propagate_taint_load_impl(unsigned int vcpu_idx, uint8_t rd, target_ulong v1, uint64_t offt, target_ulong t1, enum LOAD_TYPE lt)
{
    uint64_t vaddr = v1 + offt;

    target_ulong tout = 0;
    uint64_t paddr = 0;
    uint64_t ram_addr = 0;

    if (t1) {
        // tainted ptr implies fully tainted value!
        tout = -1;
        // tainted ptr also implies tainted PC.
        taint_pc(vcpu_idx);
        _DEBUG("Propagate load[v=0x%" PRIx64 " TAINTED]: t%" PRIu8 " <- " PRIxXLEN "\n", vaddr, rd, tout);
    }
    else {
        // else propagate the taint from the memory location.

        // adress translation FIXME: does this work or shd we also add logic in mem callback?
        qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_idx);
        paddr = qemu_plugin_vaddr_to_paddr(cs, vaddr);

        if (qemu_plugin_paddr_to_ram_addr(paddr, &ram_addr)) {
            //Non-ram location
            //FIXME: how shd we handle this?
            tout = 0;
            _DEBUG("Propagate load[v=0x%" PRIx64 ", p=0x%" PRIx64 "]: [non-RAM] location, t%" PRIu8 " <- 0x%" PRIxXLEN "\n", vaddr, paddr, rd, tout);
        }
        else
        {
            // NOTE: the loaded value is sign (/value for the U variants) extended
            // to XLEN bits before being stored in the register.
            // This means we will update all the bits in the shadow register.

            // Note that casting from short int to large uint does the sign expansion,
            // casting from short uint to large uint does not.

            switch (lt)
            {
                case LOAD_LB:
                {
                    int8_t t = 0;
                    memcpy(&t, shadow_mem + ram_addr, sizeof(t));
                    tout = t;
                    break;
                }
                case LOAD_LH:
                {
                    int16_t t = 0;
                    memcpy(&t, shadow_mem + ram_addr, sizeof(t));
                    tout = t;
                    break;
                }
                case LOAD_LW:
                {
                    int32_t t = 0;
                    memcpy(&t, shadow_mem + ram_addr, sizeof(t));
                    tout = t;
                    break;
                }
#ifdef TARGET_RISCV64
                case LOAD_LD:
                {
                    int64_t t = 0;
                    memcpy(&t, shadow_mem + ram_addr, sizeof(t));
                    tout = t;
                    break;
                }
#endif
                case LOAD_LBU:
                {
                    uint8_t t = 0;
                    memcpy(&t, shadow_mem + ram_addr, sizeof(t));
                    tout = t;
                    break;
                }
                case LOAD_LHU:
                {
                    uint16_t t = 0;
                    memcpy(&t, shadow_mem + ram_addr, sizeof(t));
                    tout = t;
                    break;
                }
#ifdef TARGET_RISCV64
                case LOAD_LWU:
                {
                    uint32_t t = 0;
                    memcpy(&t, shadow_mem + ram_addr, sizeof(t));
                    tout = t;
                    break;
                }
#endif
                default:
                {
                    fprintf(stderr, "Error: unknown load type.\n");
                    exit(1);
                }
            }
            _DEBUG("Propagate load[v=0x%" PRIx64 ", p=0x%" PRIx64 "]: t%" PRIu8 " <- t[0x%" PRIx64 "]=0x%" PRIxXLEN "\n", vaddr, paddr, rd, ram_addr, tout);
        }
    }

    shadow_regs[rd] = tout;
}

static void propagate_taint32__load(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);

    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint16_t imm0_11 = INSTR32_I_IMM_0_11_GET(instr);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);

    // The effective load address is obtained by adding register rs1 to
    // the sign-extended 12-bit offset.

    // do the sign extension, interpret as signed
    target_long imm = SIGN_EXTEND(imm0_11, 11);

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

    // FIXME Propoagate taint to the PC if applicable
    propagate_taint_load_impl(vcpu_idx, rd, v1, imm, t1, lt);
}

/***
 * FP loads
 ***/
enum FP_LOAD_TYPE {
    FP_LOAD_FLW, FP_LOAD_FLD
};

static void propagate_taint_load_fp_impl(unsigned int vcpu_idx, uint8_t rd, target_ulong v1, uint64_t offt, target_ulong t1, enum FP_LOAD_TYPE lt)
{
    uint64_t vaddr = v1 + offt;

    target_ulong tout = 0;
    uint64_t paddr = 0;
    uint64_t ram_addr = 0;

    if (t1) {
        // tainted ptr implies fully tainted value!
        tout = -1;
        // tainted ptr also implies tainted PC.
        taint_pc(vcpu_idx);

        _DEBUG("Propagate load[v=0x%" PRIx64 " TAINTED]: t%" PRIu8 " <- " PRIxXLEN "\n", vaddr, rd, tout);
    }
    else {
        // else propagate the taint from the memory location.

        // adress translation
        // FIXME: does this work or shd we also add logic in mem callback?
        qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_idx);
        paddr = qemu_plugin_vaddr_to_paddr(cs, vaddr);

        if (qemu_plugin_paddr_to_ram_addr(paddr, &ram_addr)) {
            //Non-ram location
            //FIXME: how shd we handle this?
            tout = 0;
            _DEBUG("Propagate floating-point load[v=0x%" PRIx64 ", p=0x%" PRIx64 "]: [non-RAM] location, t%" PRIu8 " <- 0x%" PRIxXLEN "\n", vaddr, paddr, rd, tout);
        }
        else {
            // NOTE: the loaded value is sign (/value for the U variants) extended
            // to XLEN bits before being stored in the register.
            // This means we will update all the bits in the shadow register.

            // Note that casting from short int to large uint does the sign expansion,
            // casting from short uint to large uint does not.

            switch (lt) {
                case FP_LOAD_FLW:
                {
                    int32_t t = 0;
                    memcpy(&t, shadow_mem + ram_addr, sizeof(t));
                    tout = t;
                    break;
                }
#ifdef TARGET_RISCVD
                case FP_LOAD_FLD:
                {
                    int64_t t = 0;
                    memcpy(&t, shadow_mem + ram_addr, sizeof(t));
                    tout = t;
                    break;
                }
#endif
                default:
                {
                    fprintf(stderr, "Error: unknown floating-point load type.\n");
                    exit(1);
                }
            }
            _DEBUG("Propagate floating-point load[v=0x%" PRIx64 ", p=0x%" PRIx64 "]: t%" PRIu8 " <- t[0x%" PRIx64 "]=0x%" PRIxXLEN "\n", vaddr, paddr, rd, ram_addr, tout);
        }
    }

    shadow_fpregs[rd] = tout;
}

static void propagate_taint32__load_fp(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);

    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint16_t imm0_11 = INSTR32_I_IMM_0_11_GET(instr);

    target_ulong t1 = shadow_regs[rs1]; // the address is taken from the integer registers.
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);

    // The effective load address is obtained by adding register rs1 to
    // the sign-extended 12-bit offset.

    // do the sign extension, interpret as signed
    target_long imm = SIGN_EXTEND(imm0_11, 11);

    static enum FP_LOAD_TYPE to_fp_load_type[] = {
        [INSTR32_F3_FLW] = FP_LOAD_FLW,
        [INSTR32_F3_FLD] = FP_LOAD_FLD,
    };
    enum FP_LOAD_TYPE lt = to_fp_load_type[f3];

    propagate_taint_load_fp_impl(vcpu_idx, rd, v1, imm, t1, lt);
}

/***
 * Stores
 ***/
enum STORE_TYPE {
    STORE_SB, STORE_SH, STORE_SW,
    STORE_SD,
};

static void propagate_taint_store_impl(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, uint64_t offt, target_ulong t1, target_ulong t2, enum STORE_TYPE st)
{
    // If the destination pointer is tainted, then we consider the PC to be tainted.
    if (t1) {
        taint_pc(vcpu_idx);
        return;
    }

    uint64_t vaddr = v1 + offt;

    // adress translation
    qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_idx);
    uint64_t paddr = qemu_plugin_vaddr_to_paddr(cs, vaddr);
    uint64_t ram_addr = 0;
    if (qemu_plugin_paddr_to_ram_addr(paddr, &ram_addr)) {
        // non-ram location, we assume that the non-ram is not tainted.
    }
    else {
        // truncate the taint when writing

        switch (st) {
            case STORE_SB:
            {
                uint8_t tout = t2;
                memcpy(shadow_mem + ram_addr, &tout, sizeof(tout));
                break;
            }
            case STORE_SH:
            {
                uint16_t tout = t2;
                memcpy(shadow_mem + ram_addr, &tout, sizeof(tout));
                break;
            }
            case STORE_SW:
            {
                uint32_t tout = t2;
                memcpy(shadow_mem + ram_addr, &tout, sizeof(tout));
                break;
            }
#ifdef TARGET_RISCV64
            case STORE_SD:
            {
                uint64_t tout = t2;
                memcpy(shadow_mem + ram_addr, &tout, sizeof(tout));
                break;
            }
#endif
            default:
            {
                fprintf(stderr, "Error: unknown store type.\n");
                exit(1);
            }
        }

        _DEBUG("Propagate store[v=0x%" PRIx64 ", p=0x%" PRIx64 "]: t[0x%" PRIx64 "] = 0x%" PRIxXLEN "\n", vaddr, paddr, ram_addr, t2);
    }
}

static void propagate_taint32__store(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);

    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint8_t rs2 = INSTR32_RS2_GET(instr);

    // imm0_11 is split in S form, the macro concatenates the two parts
    uint16_t imm0_11 = INSTR32_S_IMM_0_11_GET(instr);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];
    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    // The effective address is obtained by adding register rs1 to
    // the sign-extended 12-bit offset.

    // do the sign extension, interpret as signed
    // NOTE: we cd combine the concatenation and sign extension, but really micro-opt
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

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
 * FP stores
 ***/
enum FP_STORE_TYPE {
    FP_STORE_FSW, FP_STORE_FSD
};

static void propagate_taint_store_fp_impl(unsigned int vcpu_idx, uint8_t rd, target_ulong v1, uint64_t offt, target_ulong t1, target_fplong t2, enum FP_STORE_TYPE lt)
{
    uint64_t vaddr = v1 + offt;

    target_ulong tout = 0;
    uint64_t paddr = 0;
    uint64_t ram_addr = 0;

    // If the destination pointer is tainted, then we consider the PC to be tainted.
    if (t1) {
        taint_pc(vcpu_idx);
        return;
    }

    // else propagate the taint from the memory location.
    // adress translation
    // FIXME: does this work or shd we also add logic in mem callback?
    qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_idx);
    paddr = qemu_plugin_vaddr_to_paddr(cs, vaddr);

    if (qemu_plugin_paddr_to_ram_addr(paddr, &ram_addr)) {
        tout = 0;
        taint_pc(vcpu_idx);
        _DEBUG("Propagate floating-point store[v=0x%" PRIx64 ", p=0x%" PRIx64 "]: [non-RAM] location, t%" PRIu8 " <- 0x%" PRIxXLEN "\n", vaddr, paddr, rd, tout);
    }
    else {
        switch (lt) {
            case FP_STORE_FSW: {
                uint32_t tout = t2;
                memcpy(shadow_mem + ram_addr, &tout, sizeof(tout));
                break;
            }
#ifdef TARGET_RISCVD
            case FP_STORE_FSD: {
                uint64_t tout = t2;
                memcpy(shadow_mem + ram_addr, &tout, sizeof(tout));
                break;
            }
#endif
            default:
                fprintf(stderr, "Error: unknown floating-point store type.\n");
                exit(1);
        }
        _DEBUG("Propagate floating-point store[v=0x%" PRIx64 ", p=0x%" PRIx64 "]: t%" PRIu8 " <- t[0x%" PRIx64 "]=0x%" PRIxXLEN "\n", vaddr, paddr, rd, ram_addr, tout);
    }
}

static void propagate_taint32__store_fp(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);

    uint8_t rd = INSTR32_RD_GET(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint8_t rs2 = INSTR32_RS2_GET(instr);
    uint16_t imm0_11 = INSTR32_I_IMM_0_11_GET(instr);

    target_ulong t1 = shadow_regs[rs1]; // the address is taken from the integer registers.
    target_ulong t2 = shadow_fpregs[rs2]; // the fp taint is taken from the FP registers.
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);

    // The effective store address is obtained by adding register rs1 to
    // the sign-extended 12-bit offset.

    // do the sign extension, interpret as signed
    target_long imm = SIGN_EXTEND(imm0_11, 11);

    static enum FP_STORE_TYPE to_fp_store_type[] = {
        [INSTR32_F3_FSW] = FP_STORE_FSW,
        [INSTR32_F3_FSD] = FP_STORE_FSD,
    };
    enum FP_STORE_TYPE lt = to_fp_store_type[f3];

    propagate_taint_store_fp_impl(vcpu_idx, rd, v1, imm, t1, t2, lt);
}

/***
 * Boolean and arithmetic operations
 **/

static target_ulong propagate_taint_op__lazy(target_ulong t1, target_ulong t2)
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

    target_ulong tout = is_out_tainted ? -1ULL : 0;

    return tout;
}

// ADD and SUB: need to consider the carry.
//   - approximation: (from Valgrind's memcheck): taint everything to the left
//     of the first tainted carry.
//   - better: carry-by-carry taint propagation


static target_ulong propagate_taint__add(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2)
{
    /*
      Taint using the properties of ADD identified in the CellIFT paper.
    */

    target_ulong v1_with_ones = v1 | t1;
    target_ulong v2_with_ones = v2 | t2;

    target_ulong v1_with_zeros = v1 & (~t1);
    target_ulong v2_with_zeros = v2 & (~t2);

    // Taint:
    // 1. taint directly from input bit to the corresponding output bit
    // 2. taint from carries

    target_ulong sum_with_ones = v1_with_ones + v2_with_ones;
    target_ulong sum_with_zeros = v1_with_zeros + v2_with_zeros;

    target_ulong tout = t1 | t2 | (sum_with_ones ^ sum_with_zeros);

    return tout;
}


static void propagate_taint_ADD(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong tout = propagate_taint__add(vals.v1, vals.v2, t1, t2);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate ADD(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);
}

static void propagate_taint_ADDI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // Acceptable precision is important bc "mov rd,rs" is just an alias for "addi rd,rs,0"
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

    _DEBUG("Propagate ADDI(r%d=0x%" PRIxXLEN ",imm=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, v1, imm, rd);

    target_ulong t1 = shadow_regs[rs1];

    target_ulong tout = propagate_taint__add(v1, imm, t1, 0);

    shadow_regs[rd] = tout;

    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);
}


static target_ulong propagate_taint__sub(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2)
{
    target_ulong v1_with_ones = v1 | t1;
    target_ulong v2_with_ones = v2 | t2;

    target_ulong v1_with_zeros = v1 & (~t1);
    target_ulong v2_with_zeros = v2 & (~t2);

    // Taint:
    // 1. taint directly from input bit to the corresponding output bit
    // 2. taint from carries

    target_ulong diff_zero_ones = v1_with_zeros - v2_with_ones;
    target_ulong diff_ones_zeros = v1_with_ones - v2_with_zeros;

    target_ulong tout = t1 | t2 | (diff_zero_ones ^ diff_ones_zeros);
    return tout;
}

static void propagate_taint_SUB(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong tout = propagate_taint__sub(vals.v1, vals.v2, t1, t2);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SUB(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);
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

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    target_ulong tA = (~t1) & vals.v1 & t2;
    target_ulong tB = t1 & (~t2) & vals.v2;
    target_ulong tC = t1 & t2;
    target_ulong tout = tA | tB | tC;

    shadow_regs[rd] = tout;

    _DEBUG("Propagate AND(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);


}

static void propagate_taint_ANDI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    /*
     * With T2 = 0, the taint propagation simplifies to
     * AND: (T1 * V2)
     */

    target_ulong tout = t1 & imm;
    shadow_regs[rd] = tout;

    _DEBUG("Propagate ANDI(r%d=0x%" PRIxXLEN ",imm=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, v1, imm, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);


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

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    target_ulong tA = (~t1) & (~vals.v1) & t2;
    target_ulong tB = t1 & (~t2) & (~vals.v2);
    target_ulong tC = t1 & t2;
    target_ulong tout = tA | tB | tC;

    shadow_regs[rd] = tout;

    _DEBUG("Propagate OR(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);

}


static void propagate_taint_ORI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    /*
     * With T2 = 0, the taint propagation simplifies to
     * OR: (T1 * (NOT V2))
     */

    target_ulong tout = t1 & (~imm);
    shadow_regs[rd] = tout;


    _DEBUG("Propagate ORI(r%d=0x%" PRIxXLEN ",imm=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, v1, imm, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);

}


// XOR

static void propagate_taint_XOR(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    /*
     * XOR: union of the taints.
     *
     * Exception: if rs1 is rs2, then the output is always 0.
     */

    target_ulong tout = 0;
    target_ulong t1 = 0, t2 = 0;
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
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);


}


static void propagate_taint_XORI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    /*
     * XOR: union of the taints.
     */

    target_ulong t1 = shadow_regs[rs1];
    target_ulong tout = t1;
    shadow_regs[rd] = t1;

    _DEBUG("Propagate XORI(X, X) -> r%" PRIu8 "\n", rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);
}


// SLL, SRL, SRA

/*
* Shifts
*
* eg left shift:
* rd <- (uint)rs1 << rs2[0:X]
*
* SLL, SRL, and SRA perform logical left, logical right, and arithmetic right shifts on the value in
* register rs1 by the shift amount held in the lower X bits of register rs2.
*
* /!\ RV32: the lower 5 bits
*     RV64: the lower 6 bits
*/

static target_ulong propagate_taint_sll_impl(target_ulong v1, target_ulong t1, target_ulong v2, target_ulong t2, int shamtsize)
{
    /*
     * t1 => left shift the tainted bits (by the X lsb of rs2)
     * t2 => if rs1 != 0, everything is tainted
     */

    target_ulong mask = MASK(shamtsize);
    unsigned int shamt = v2 & mask;
    uint8_t t_shift = t2 & mask;

    target_ulong tA = t1 << shamt;
    target_ulong tB = (t_shift && (v1 != 0)) ? -1 : 0;

    target_ulong tout = tA | tB;

    return tout;
}

static void propagate_taint_SLL(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    target_ulong tout = propagate_taint_sll_impl(vals.v1, t1, vals.v2, t2, SHIFTS_SHAMT_SIZE);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLL(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);

}



static void propagate_taint_SLLI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint64_t imm)
{
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    // /!\ SHAMT_SIZE depends on RV32 or RV64 !
    target_ulong tout = propagate_taint_sll_impl(v1, t1, imm, 0, SHIFTS_SHAMT_SIZE);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLLI(0x%" PRIxXLEN ", imm=0x%" PRIx16 ") -> r%" PRIu8 "\n", v1, imm, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);


}


static target_ulong propagate_taint_srl_impl(target_ulong v1, target_ulong t1, target_ulong v2, target_ulong t2, int shamtsize)
{


    /*
     * t1 => right shift the tainted bits (by the X lsb of rs2)
     * t2 => if rs1 != 0, everything is tainted
     */


    target_ulong mask = MASK(shamtsize);
    unsigned int shamt = v2 & mask;
    uint8_t t_shift = t2 & mask;

    target_ulong tA = t1 >> shamt;
    target_ulong tB = (t_shift && (v1 != 0)) ? -1 : 0;

    target_ulong tout = tA | tB;

    return tout;
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

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    target_ulong tout = propagate_taint_srl_impl(vals.v1, t1, vals.v2, t2, SHIFTS_SHAMT_SIZE);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SRL(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);

}


static void propagate_taint_SRLI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm)
{
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    target_ulong tout = propagate_taint_srl_impl(v1, t1, imm, 0, SHIFTS_SHAMT_SIZE);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SRLI(0x%" PRIxXLEN ", imm=0x%" PRIx16 ") -> r%" PRIu8 "\n", v1, imm, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);

}


static target_ulong propagate_taint_sra_impl(target_ulong v1, target_ulong t1, target_ulong v2, target_ulong t2, int shamtsize)
{

    target_ulong mask = MASK(shamtsize);

    /*
     * t1 => right shift the tainted bits (by the X lsb of rs2)
     *       since the MSB is replicated by the shift, we also want to
     *       propagate the taint of the MSB during the shift => arithmetic shift
     * t2 => if rs1 != 0 AND rs1 != 0x11..1, everything is tainted
     */

    uint8_t shift = v2 & mask;
    uint8_t t_shift = t2 & mask;

    target_ulong tA = ((target_long)t1) >> shift;
    target_ulong tB = (t_shift && (v1 != 0) && (v1 != -1)) ? -1 : 0;

    target_ulong tout = tA | tB;

    return tout;
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

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    target_ulong tout = propagate_taint_sra_impl(vals.v1, t1, vals.v2, t2, SHIFTS_SHAMT_SIZE);


    shadow_regs[rd] = tout;

    _DEBUG("Propagate SRA(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);

}

static void propagate_taint_SRAI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm)
{
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    target_ulong tout = propagate_taint_sra_impl(v1, t1, imm, 0, SHIFTS_SHAMT_SIZE);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SRAI(0x%" PRIxXLEN ", imm=%0x" PRIx16 ") -> r%" PRIu8 "\n", v1, imm, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);


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
static target_ulong taint_result__sltu(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2)
{
    target_ulong v1_with_ones =  v1 | t1;
    target_ulong v2_with_ones =  v2 | t2;

    target_ulong v1_with_zeros =  v1 & (~t1);
    target_ulong v2_with_zeros =  v2 & (~t2);

    target_ulong stable_compare1 = v1_with_ones < v2_with_zeros;
    target_ulong stable_compare2 = v1_with_zeros >= v2_with_ones;

    target_ulong stable_compare = stable_compare1 | stable_compare2;

    return (! stable_compare);
}

static void propagate_taint_SLTU(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);
    target_ulong tout = taint_result__sltu(vals.v1, vals.v2, t1, t2);
    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLTU(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);

}

static void propagate_taint_SLTIU(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

    target_ulong t1 = shadow_regs[rs1];

    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong tout = taint_result__sltu(v1, imm, t1, 0);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLTIU(r%d=0x%" PRIxXLEN ",imm=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", v1, rs1, imm, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);


}

// logic used for SLT and SLTI
static target_ulong taint_result__slt(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2)
{
    target_ulong v1_with_ones =  v1 | t1;
    target_ulong v2_with_ones =  v2 | t2;

    target_ulong v1_with_zeros =  v1 & (~t1);
    target_ulong v2_with_zeros =  v2 & (~t2);

    // Swap the sign bit between the "with ones" and "with zeros" to get the
    // max and min values
    // (max is all 1s, except for sign bit ; min is all 0s, except for sign bit)
    // and cast to int to get a signed comparison
    target_long v1_max = (v1_with_zeros & (1ULL << (RISCV_XLEN-1))) | (v1_with_ones & MASK(RISCV_XLEN-1));
    target_long v2_max = (v2_with_zeros & (1ULL << (RISCV_XLEN-1))) | (v2_with_ones & MASK(RISCV_XLEN-1));

    target_long v1_min = (v1_with_ones & (1ULL << (RISCV_XLEN-1))) | (v1_with_zeros & MASK(RISCV_XLEN-1));
    target_long v2_min = (v2_with_ones & (1ULL << (RISCV_XLEN-1))) | (v2_with_zeros & MASK(63));

    uint8_t stable_compare1 = v1_max < v2_min;
    uint8_t stable_compare2 = v1_min < v2_max;

    uint8_t stable_compare = stable_compare1 | stable_compare2;

    return (! stable_compare);

}

static void propagate_taint_SLT(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);
    target_ulong tout = taint_result__slt(vals.v1, vals.v2, t1, t2);
    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLT(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);

}

static void propagate_taint_SLTI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

    target_ulong t1 = shadow_regs[rs1];

    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong tout = taint_result__slt(v1, imm, t1, 0);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate SLTIU(r%d=0x%" PRIxXLEN ",imm=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, v1, imm, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rd, tout);
}


// AUIPC and LUI (RV64 only)

static void propagate_taint32_AUIPC(unsigned int vcpu_idx, uint32_t instr)
{
    target_ulong imm31_12 = INSTR32_U_IMM_12_31_GET(instr);
    uint8_t rd = INSTR32_RD_GET(instr);

    // AUIPC appends 12 low-order zero bits to the 20-bit
    // U-immediate, sign-extends the result to XLEN bits,
    // adds it to the address of the AUIPC instruction (pc),
    // then places the result in register rd.

    target_ulong imm31_0 = imm31_12 << 12;

    // do the sign extension, interpret as signed
    target_long imm = SIGN_EXTEND(imm31_0, 31);

    target_ulong tout = 0;
    shadow_regs[rd] = tout;


    _DEBUG("Propagate AUIPC(0x%" PRIxXLEN ") -> r%" PRIu8 "\n", imm, rd);
    _DEBUG(" -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rd, tout);
}

static void propagate_taint32_LUI(unsigned int vcpu_idx, uint32_t instr)
{
    target_ulong imm31_12 = INSTR32_U_IMM_12_31_GET(instr);
    uint8_t rd = INSTR32_RD_GET(instr);

    // LUI places the 20-bit U-immediate
    // into bits 31–12 of register rd and places zero in the lowest 12 bits.

    // The 32-bit result is sign-extended to XLEN bits.

    // Taint-wise: clears rd!

    target_ulong imm31_0 = imm31_12 << 12;
    target_long imm = SIGN_EXTEND(imm31_0, 31);

    target_ulong tout = 0;
    shadow_regs[rd] = tout;

    _DEBUG("Propagate LUI(0x%" PRIxXLEN ") -> r%" PRIu8 "\n", imm, rd);
    _DEBUG(" -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rd, tout);

}


/***
 * M extension
 ***/

static void propagate_taint_MUL_DIV(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong tout = propagate_taint_op__lazy(t1, t2);

    shadow_regs[rd] = tout;

    _DEBUG("Propagate MUL(r%d=0x%" PRIxXLEN ",r%d=0x%" PRIxXLEN ") -> r%" PRIu8 "\n", rs1, vals.v1, rs2, vals.v2, rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "  t%" PRIu8 " = 0x%" PRIxXLEN " -> t%" PRIu8 " = 0x%" PRIxXLEN "\n", rs1, t1, rs2, t2, rd, tout);
}

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

/**
 * Branches
 */

enum BRANCH_TYPE {
    BRANCH_FUNC7_BEQ  = 0b000,
    BRANCH_FUNC7_BNE  = 0b001,
    BRANCH_FUNC7_BLT  = 0b100,
    BRANCH_FUNC7_BGE  = 0b101,
    BRANCH_FUNC7_BLTU = 0b110,
    BRANCH_FUNC7_BGEU = 0b111,
};

static void propagate_taint32__beq_bne(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2) {
    // Check whether all bits at non-tainted indices are equal. If not, then taints will not be able to make a change in the output.
    target_ulong non_tainted_bits_1 = v1 & ~(t1 | t2);
    target_ulong non_tainted_bits_2 = v2 & ~(t1 | t2);

    if (non_tainted_bits_1 != non_tainted_bits_2)
        return;

    // If there is at least one tainted bit, then the output will be tainted.
    if (t1 | t2)
        taint_pc(vcpu_idx);
}

static void propagate_taint32__blt(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2) {
    // If no input is tainted, we know already that the PC will also not be tainted. This conditional is for performance only and can be omitted.
    if (!(t1 | t2))
        return;

    // Maximize left and right and see whether there are changes possible.
    // Since the operation is signed, minimizing implies setting the MSB if possible.
    target_ulong min1_lsbs = (v1 & ~t1) & MASK(RISCV_XLEN-1);
    target_ulong min1_msb  = (v1 | t1)  & (1ULL << (RISCV_XLEN-1));
    target_ulong min2_lsbs = (v2 & ~t2) & MASK(RISCV_XLEN-1);
    target_ulong min2_msb  = (v2 | t2)  & (1ULL << (RISCV_XLEN-1));
    target_ulong min1 = min1_msb | min1_lsbs;
    target_ulong min2 = min2_msb | min2_lsbs;

    target_ulong max1_lsbs = (v1 | t1)  & MASK(RISCV_XLEN-1);
    target_ulong max1_msb  = (v1 & ~t1) & (1ULL << (RISCV_XLEN-1));
    target_ulong max2_lsbs = (v2 | t2)  & MASK(RISCV_XLEN-1);
    target_ulong max2_msb  = (v2 & ~t2) & (1ULL << (RISCV_XLEN-1));
    target_ulong max1 = max1_msb | max1_lsbs;
    target_ulong max2 = max2_msb | max2_lsbs;

    // This is a signed comparison.
    target_long max_output = ((target_long) min1) < ((target_long) max2);
    target_long min_output = ((target_long) max1) < ((target_long) min2);

    if (min_output != max_output)
        taint_pc(vcpu_idx);
}

static void propagate_taint32__bge(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2) {
    // If no input is tainted, we know already that the PC will also not be tainted. This conditional is for performance only and can be omitted.
    if (!(t1 | t2))
        return;

    // Maximize left and right and see whether there are changes possible.
    // Since the operation is signed, minimizing implies setting the MSB if possible.
    target_ulong min1_lsbs = (v1 & ~t1) & MASK(RISCV_XLEN-1);
    target_ulong min1_msb  = (v1 | t1)  & (1ULL << (RISCV_XLEN-1));
    target_ulong min2_lsbs = (v2 & ~t2) & MASK(RISCV_XLEN-1);
    target_ulong min2_msb  = (v2 | t2)  & (1ULL << (RISCV_XLEN-1));
    target_ulong min1 = min1_msb | min1_lsbs;
    target_ulong min2 = min2_msb | min2_lsbs;

    target_ulong max1_lsbs = (v1 | t1)  & MASK(RISCV_XLEN-1);
    target_ulong max1_msb  = (v1 & ~t1) & (1ULL << (RISCV_XLEN-1));
    target_ulong max2_lsbs = (v2 | t2)  & MASK(RISCV_XLEN-1);
    target_ulong max2_msb  = (v2 & ~t2) & (1ULL << (RISCV_XLEN-1));
    target_ulong max1 = max1_msb | max1_lsbs;
    target_ulong max2 = max2_msb | max2_lsbs;

    // This is a signed comparison.
    target_long max_output = ((target_long) min1) >= ((target_long) max2);
    target_long min_output = ((target_long) max1) >= ((target_long) min2);

    if (min_output != max_output)
        taint_pc(vcpu_idx);
}

static void propagate_taint32__bltu(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2) {
    // If no input is tainted, we know already that the PC will also not be tainted. This conditional is for performance only and can be omitted.
    if (!(t1 | t2))
        return;

    // Maximize left and right and see whether there are changes possible.
    // Since the operation is unsigned, minimizing implies simply unsetting the tainted bits.
    target_ulong min1 = (v1 & ~t1);
    target_ulong min2 = (v2 & ~t2);
    target_ulong max1 = (v1 |  t1);
    target_ulong max2 = (v2 |  t2);

    // This is a signed comparison.
    target_ulong max_output = min1 < max2;
    target_ulong min_output = max1 < min2;

    if (min_output != max_output)
        taint_pc(vcpu_idx);
}

static void propagate_taint32__bgeu(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2) {
    // If no input is tainted, we know already that the PC will also not be tainted. This conditional is for performance only and can be omitted.
    if (!(t1 | t2))
        return;

    // Maximize left and right and see whether there are changes possible.
    // Since the operation is unsigned, minimizing implies simply unsetting the tainted bits.
    target_ulong min1 = (v1 & ~t1);
    target_ulong min2 = (v2 & ~t2);
    target_ulong max1 = (v1 |  t1);
    target_ulong max2 = (v2 |  t2);

    // This is a signed comparison.
    target_ulong max_output = min1 < max2;
    target_ulong min_output = max1 < min2;

    if (min_output != max_output)
        taint_pc(vcpu_idx);
}


static void propagate_taint32__branch(unsigned int vcpu_idx, uint32_t instr)
{
    uint8_t f3 = INSTR32_GET_FUNCT3(instr);
    uint8_t rs1 = INSTR32_RS1_GET(instr);
    uint8_t rs2 = INSTR32_RS2_GET(instr);

    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong v2 = get_one_reg_value(vcpu_idx, rs2);
    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    switch (f3) {
        case BRANCH_FUNC7_BEQ:
        case BRANCH_FUNC7_BNE:
            propagate_taint32__beq_bne(vcpu_idx, v1, v2, t1, t2);
            break;
        case BRANCH_FUNC7_BLT:
            propagate_taint32__blt(vcpu_idx, v1, v2, t1, t2);
            break;
        case BRANCH_FUNC7_BGE:
            propagate_taint32__bge(vcpu_idx, v1, v2, t1, t2);
            break;
        case BRANCH_FUNC7_BLTU:
            propagate_taint32__bltu(vcpu_idx, v1, v2, t1, t2);
            break;
        case BRANCH_FUNC7_BGEU:
            propagate_taint32__bgeu(vcpu_idx, v1, v2, t1, t2);
            break;
        default:
            fprintf(stderr, "Unknown opcode for branch instr: 0x%" PRIx32 "\n", instr);
            break;
    }
}

static void propagate_taint32_JAL(unsigned int vcpu_idx, uint32_t instr)
{
    // unconditionnal jump with an immediate.
    // As we ignore the taint of the immediate for now, this has no architectural IFT impact.
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


