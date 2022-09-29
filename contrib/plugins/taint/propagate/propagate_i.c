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

static void propagate_taint32_auipc(unsigned int vcpu_idx, uint8_t rd)
{
    // Do nothing much. We ignore register taints if the PC is tainted.
    // If the PC and the instruction are both not tainted, then rd will also be non-tainted.
    // In the latter case, we clean the destination register's taint.
    if (get_pc_taint())
        shadow_regs[rd] = -1ULL;
    else
        shadow_regs[rd] = 0;
}

static void propagate_taint32_lui(unsigned int vcpu_idx, uint8_t rd)
{
    // We assume that the instruction (and hence the immediate) is not tainted.
    shadow_regs[rd] = 0;
}

static void propagate_taint32_jal(unsigned int vcpu_idx, uint8_t rd)
{
    // We assume that the instruction (and hence the immediate) is not tainted.
    if (get_pc_taint())
        shadow_regs[rd] = -1ULL;
    else
        shadow_regs[rd] = 0;

}

static void propagate_taint32_JALR(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1)
{
    // Two actions:
    // - Clears the taint in rd
    if (get_pc_taint())
        shadow_regs[rd] = -1ULL;
    else
        shadow_regs[rd] = 0;
    // - Taints the PC if rs is tainted
    target_ulong rs_shadowval = shadow_regs[rs1];

    if (rs_shadowval)
        taint_pc(vcpu_idx);
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

static void propagate_taint_addi(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // Acceptable precision is important bc "mov rd,rs" is just an alias for "addi rd,rs,0"
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);


    target_ulong t1 = shadow_regs[rs1];

    target_ulong tout = propagate_taint__add(v1, imm, t1, 0);

    shadow_regs[rd] = tout;
}

static void propagate_taint_slti(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

    target_ulong t1 = shadow_regs[rs1];

    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong tout = taint_result__slt(v1, imm, t1, 0);

    shadow_regs[rd] = tout;
}

static void propagate_taint_sltiu(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

    target_ulong t1 = shadow_regs[rs1];

    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong tout = taint_result__sltu(v1, imm, t1, 0);

    shadow_regs[rd] = tout;
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

static void propagate_taint_xori(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    target_ulong t1 = shadow_regs[rs1];
    shadow_regs[rd] = t1;
}

static void propagate_taint_xori(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    target_ulong t1 = shadow_regs[rs1];
    shadow_regs[rd] = t1;
}

static void propagate_taint_ORI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs and sign extended to XLEN bits.
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    // What is set to 1 by the imm cannot be tainted.
    target_ulong tout = t1 & (~imm);
    shadow_regs[rd] = tout;
}

static void propagate_taint_ANDI(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    target_ulong tout = t1 & imm;
    shadow_regs[rd] = tout;
}
