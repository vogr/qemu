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

// Prototypes for utility functions
static target_ulong taint_result_slt_impl(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2);
static target_ulong propagate_taint32_sll_impl(target_ulong v1, target_ulong t1, target_ulong v2, target_ulong t2, int shamtsize);
static target_ulong propagate_taint32_srl_impl(target_ulong v1, target_ulong t1, target_ulong v2, target_ulong t2, int shamtsize);
static target_ulong propagate_taint32_sra_impl(target_ulong v1, target_ulong t1, target_ulong v2, target_ulong t2, int shamtsize);
static target_ulong propagate_taint32_add_impl(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2);
static target_ulong propagate_taint32_sub_impl(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2);
static target_ulong taint_result_sltu_impl(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2);

// Prototypes for post-dispatch functions
static void propagate_taint32_auipc(unsigned int vcpu_idx, uint8_t rd);
static void propagate_taint32_lui(unsigned int vcpu_idx, uint8_t rd);
static void propagate_taint32_jal(unsigned int vcpu_idx, uint8_t rd);
static void propagate_taint32_jalr(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1);
static void propagate_taint32__beq_bne(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2);
static void propagate_taint32__blt(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2);
static void propagate_taint32__bge(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2);
static void propagate_taint32__bltu(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2);
static void propagate_taint32__bgeu(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2);
static void propagate_taint32__branch(unsigned int vcpu_idx, uint32_t instr);
static void propagate_taint32_load(unsigned int vcpu_idx, uint32_t instr);
static void propagate_taint32_store(unsigned int vcpu_idx, uint32_t instr);
static void propagate_taint32_addi(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11);
static void propagate_taint32_slti(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11);
static void propagate_taint32_sltiu(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11);
static void propagate_taint32_xori(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11);
static void propagate_taint32_xori(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11);
static void propagate_taint32_ori(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11);
static void propagate_taint32_andi(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11);
static void propagate_taint32_slli(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint64_t imm);
static void propagate_taint32_srli(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm);
static void propagate_taint32_srai(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm);
static void propagate_taint32_add(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_sub(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_sll(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_slt(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_sltu(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_xor(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_srl(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_sra(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_or(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_and(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_fence(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1);
static void propagate_taint32_addiw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11);
static void propagate_taint32_slliw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint64_t imm);
static void propagate_taint32_srliw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint64_t imm);
static void propagate_taint32_sraiw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint64_t imm);
static void propagate_taint32_addw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_subw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_sllw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_srlw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);
static void propagate_taint32_sraw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2);

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

static void propagate_taint32_jalr(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1)
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

    // If rs1 == rs2, the result never depends on the stored values, therefore the PC will not be tainted by this operation.
    if (rs1 == rs2)
        return;

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

static void propagate_taint32_load_impl(unsigned int vcpu_idx, uint8_t rd, target_ulong v1, uint64_t offt, target_ulong t1, enum LOAD_TYPE lt)
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

static void propagate_taint32_load(unsigned int vcpu_idx, uint32_t instr)
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
    propagate_taint32_load_impl(vcpu_idx, rd, v1, imm, t1, lt);
}

/***
 * Stores
 ***/
enum STORE_TYPE {
    STORE_SB, STORE_SH, STORE_SW,
    STORE_SD,
};

static void propagate_taint32_store_impl(unsigned int vcpu_idx, target_ulong v1, target_ulong v2, uint64_t offt, target_ulong t1, target_ulong t2, enum STORE_TYPE st)
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

static void propagate_taint32_store(unsigned int vcpu_idx, uint32_t instr)
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

    propagate_taint32_store_impl(vcpu_idx, vals.v1, vals.v2, imm, t1, t2, st);
}

static void propagate_taint32_addi(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // Acceptable precision is important bc "mov rd,rs" is just an alias for "addi rd,rs,0"
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);


    target_ulong t1 = shadow_regs[rs1];

    target_ulong tout = propagate_taint32_add_impl(v1, imm, t1, 0);

    shadow_regs[rd] = tout;
}

static void propagate_taint32_slti(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

    target_ulong t1 = shadow_regs[rs1];

    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong tout = taint_result_slt_impl(v1, imm, t1, 0);

    shadow_regs[rd] = tout;
}

static void propagate_taint32_sltiu(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

    target_ulong t1 = shadow_regs[rs1];

    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong tout = taint_result_sltu_impl(v1, imm, t1, 0);

    shadow_regs[rd] = tout;
}

// logic used for SLT and SLTI
static target_ulong taint_result_slt_impl(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2)
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

static void propagate_taint32_xori(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    target_ulong t1 = shadow_regs[rs1];
    shadow_regs[rd] = t1;
}

static void propagate_taint32_xori(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    target_ulong t1 = shadow_regs[rs1];
    shadow_regs[rd] = t1;
}

static void propagate_taint32_ori(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs and sign extended to XLEN bits.
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    // What is set to 1 by the imm cannot be tainted.
    target_ulong tout = t1 & (~imm);
    shadow_regs[rd] = tout;
}

static void propagate_taint32_andi(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // imm is 12 bits longs ans sign extended to XLEN bits.
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    target_ulong tout = t1 & imm;
    shadow_regs[rd] = tout;
}

// Utility function for SLL and SLLI and length-varying variants
static target_ulong propagate_taint32_sll_impl(target_ulong v1, target_ulong t1, target_ulong v2, target_ulong t2, int shamtsize)
{
    /*
     * t1 => left shift the tainted bits (by the X lsb of rs2)
     * t2 => if rs1 != 0, everything is tainted
     */

    target_ulong mask = MASK(shamtsize);
    unsigned int shamt = v2 & mask;
    uint8_t t_shift = t2 & mask;

    target_ulong tA = t1 << shamt;
    target_ulong tB = (t_shift && (v1 != 0)) ? -1ULL : 0;

    target_ulong tout = tA | tB;

    return tout;
}

static void propagate_taint32_slli(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint64_t imm)
{
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    // SHAMT_SIZE depends on RV32 or RV64
    target_ulong tout = propagate_taint32_sll_impl(v1, t1, imm, 0, SHIFTS_SHAMT_SIZE);

    shadow_regs[rd] = tout;
}

// Utility function for SRL and SRLI and length-varying variants
static target_ulong propagate_taint32_srl_impl(target_ulong v1, target_ulong t1, target_ulong v2, target_ulong t2, int shamtsize)
{
    /*
     * t1 => right shift the tainted bits (by the X lsb of rs2)
     * t2 => if rs1 != 0, everything is tainted
     */

    target_ulong mask = MASK(shamtsize);
    unsigned int shamt = v2 & mask;
    uint8_t t_shift = t2 & mask;

    target_ulong tA = t1 >> shamt;
    target_ulong tB = (t_shift && (v1 != 0)) ? -1ULL : 0;

    target_ulong tout = tA | tB;

    return tout;
}

static void propagate_taint32_srli(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm)
{
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    target_ulong tout = propagate_taint32_srl_impl(v1, t1, imm, 0, SHIFTS_SHAMT_SIZE);

    shadow_regs[rd] = tout;
}

// Utility function for SRA and SRAI and length-varying variants
static target_ulong propagate_taint32_sra_impl(target_ulong v1, target_ulong t1, target_ulong v2, target_ulong t2, int shamtsize)
{
    /*
     * t1 => right shift the tainted bits (by the X lsb of rs2)
     *       since the MSB is replicated by the shift, we also want to
     *       propagate the taint of the MSB during the shift => arithmetic shift
     * t2 => if rs1 != 0 AND rs1 != 0x11..1, everything is tainted
     */

    target_ulong mask = MASK(shamtsize);

    uint8_t shift = v2 & mask;
    uint8_t t_shift = t2 & mask;

    target_ulong tA = ((target_long)t1) >> shift;
    target_ulong tB = (t_shift && (v1 != 0) && (v1 != -1)) ? -1ULL : 0;

    target_ulong tout = tA | tB;

    return tout;
}

static void propagate_taint32_srai(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm)
{
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    target_ulong tout = propagate_taint32_sra_impl(v1, t1, imm, 0, SHIFTS_SHAMT_SIZE);

    shadow_regs[rd] = tout;
}

// Utility function for ADD and ADDI and length-varying variants
static target_ulong propagate_taint32_add_impl(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2)
{
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

static void propagate_taint32_add(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong tout = propagate_taint32_add_impl(vals.v1, vals.v2, t1, t2);

    shadow_regs[rd] = tout;
}

// Utility function for SUB and SUBI and length-varying variants
static target_ulong propagate_taint32_sub_impl(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2)
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

static void propagate_taint32_sub(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    // If rs1 == rs2, then no taint propagates and the outputis simply zero.
    if (rs1 == rs2) {
        shadow_regs[rd] = 0;
        return;
    }

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong tout = propagate_taint32_sub_impl(vals.v1, vals.v2, t1, t2);

    shadow_regs[rd] = tout;
}

static void propagate_taint32_sll(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    // SHAMT_SIZE depends on RV32 or RV64
    target_ulong tout = propagate_taint32_sll_impl(vals.v1, t1, vals.v2, t2, SHIFTS_SHAMT_SIZE);

    shadow_regs[rd] = tout;
}

static void propagate_taint32_slt(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    if (rs1 == rs2)
        return;

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);
    target_ulong tout = taint_result_slt_impl(vals.v1, vals.v2, t1, t2);
    shadow_regs[rd] = tout;
}

static target_ulong taint_result_sltu_impl(target_ulong v1, target_ulong v2, target_ulong t1, target_ulong t2)
{
    // Logic is described in the CellIFT paper.

    target_ulong v1_with_ones =  v1 | t1;
    target_ulong v2_with_ones =  v2 | t2;

    target_ulong v1_with_zeros =  v1 & (~t1);
    target_ulong v2_with_zeros =  v2 & (~t2);

    target_ulong stable_compare1 = v1_with_ones < v2_with_zeros;
    target_ulong stable_compare2 = v1_with_zeros >= v2_with_ones;

    target_ulong stable_compare = stable_compare1 | stable_compare2;

    return (! stable_compare);
}

static void propagate_taint32_sltu(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    if (rs1 == rs2)
        return;

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);
    target_ulong tout = taint_result_sltu_impl(vals.v1, vals.v2, t1, t2);
    shadow_regs[rd] = tout;
}

static void propagate_taint32_xor(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    /*
     * XOR: union of the taints.
     * Exception: if rs1 is rs2, then the output is always 0.
     */

    if (rs1 == rs2) {
        shadow_regs[rd] = 0;
        return;
    }

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];
    target_ulong tout = t1 | t2;
    shadow_regs[rd] = tout;
}

static void propagate_taint32_srl(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
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

    target_ulong tout = propagate_taint32_srl_impl(vals.v1, t1, vals.v2, t2, SHIFTS_SHAMT_SIZE);

    shadow_regs[rd] = tout;
}

static void propagate_taint32_sra(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
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

    target_ulong tout = propagate_taint32_sra_impl(vals.v1, t1, vals.v2, t2, SHIFTS_SHAMT_SIZE);

    shadow_regs[rd] = tout;
}

static void propagate_taint32_or(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
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

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    target_ulong tA = (~t1) & (~vals.v1) & t2;
    target_ulong tB = t1 & (~t2) & (~vals.v2);
    target_ulong tC = t1 & t2;
    target_ulong tout = tA | tB | tC;

    shadow_regs[rd] = tout;
}

static void propagate_taint32_and(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
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

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    target_ulong tA = (~t1) & vals.v1 & t2;
    target_ulong tB = t1 & (~t2) & vals.v2;
    target_ulong tC = t1 & t2;
    target_ulong tout = tA | tB | tC;

    shadow_regs[rd] = tout;
}

static void propagate_taint32_fence(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1)
{
    // Future: Fence may taint the PC if rs1 is tainted, and may clear rd.
    return;
}

/**
  * 64-bit-only instructions
*/

static void propagate_taint32_addiw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint16_t imm0_11)
{
    // Acceptable precision is important bc "mov rd,rs" is just an alias for "addi rd,rs,0"
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong imm = SIGN_EXTEND(imm0_11, 11);

    target_ulong t1 = shadow_regs[rs1];

    struct taint_vals_w in_w = truncate_vals_taint(v1, imm, t1, 0);

    target_ulong tout_low = propagate_taint32_add_impl(in_w.v1, in_w.v2, in_w.t1, in_w.t2);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);

}

static void propagate_taint32_slliw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint64_t imm)
{
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    struct taint_vals_w in_w = truncate_vals_taint(v1, imm, t1, 0);

    // SHAMT_SIZE is fixed as if RV32, i.e. to 5
    target_ulong tout_low = propagate_taint32_sll_impl(in_w.v1, in_w.t1, in_w.v2, in_w.t2, 5);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);
}

static void propagate_taint32_srliw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint64_t imm)
{
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    struct taint_vals_w in_w = truncate_vals_taint(v1, imm, t1, 0);

    // SHAMT_SIZE is fixed as if RV32, i.e. to 5
    target_ulong tout_low = propagate_taint32_srl_impl(in_w.v1, in_w.t1, in_w.v2, in_w.t2, 5);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);
}

static void propagate_taint32_sraiw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint64_t imm)
{
    target_ulong v1 = get_one_reg_value(vcpu_idx, rs1);
    target_ulong t1 = shadow_regs[rs1];

    struct taint_vals_w in_w = truncate_vals_taint(v1, imm, t1, 0);

    // SHAMT_SIZE is fixed as if RV32, i.e. to 5
    target_ulong tout_low = propagate_taint32_sra_impl(in_w.v1, in_w.t1, in_w.v2, in_w.t2, 5);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);
}

static void propagate_taint32_addw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    struct taint_vals_w in_w = truncate_vals_taint(vals.v1, vals.v2, t1, t2);

    target_ulong tout_low = propagate_taint32_add_impl(in_w.v1, in_w.v2, in_w.t1, in_w.t2);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);
}

static void propagate_taint32_subw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{
    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    struct taint_vals_w in_w = truncate_vals_taint(vals.v1, vals.v2, t1, t2);

    target_ulong tout_low = propagate_taint32_sub_impl(in_w.v1, in_w.v2, in_w.t1, in_w.t2);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);
}


static void propagate_taint32_sllw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct taint_vals_w in_w = truncate_vals_taint(vals.v1, vals.v2, t1, t2);

    // SHAMT_SIZE is fixed as if RV32, i.e. to 5
    target_ulong tout_low = propagate_taint32_sll_impl(in_w.v1, in_w.t1, in_w.v2, in_w.t2, 5);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);
}

static void propagate_taint32_srlw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct taint_vals_w in_w = truncate_vals_taint(vals.v1, vals.v2, t1, t2);

    // SHAMT_SIZE is fixed as if RV32, i.e. to 5
    target_ulong tout_low = propagate_taint32_srl_impl(in_w.v1, in_w.t1, in_w.v2, in_w.t2, 5);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);
}

static void propagate_taint32_sraw(unsigned int vcpu_idx, uint8_t rd, uint8_t rs1, uint8_t rs2)
{

    struct src_regs_values vals = get_src_reg_values(vcpu_idx, rs1, rs2);

    target_ulong t1 = shadow_regs[rs1];
    target_ulong t2 = shadow_regs[rs2];

    struct taint_vals_w in_w = truncate_vals_taint(vals.v1, vals.v2, t1, t2);

    // SHAMT_SIZE is fixed as if RV32, i.e. to 5
    target_ulong tout_low = propagate_taint32_sra_impl(in_w.v1, in_w.t1, in_w.v2, in_w.t2, 5);
    target_ulong tout = SIGN_EXTEND(tout_low, 31);
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
            propagate_taint32_addi(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_SLTI:
        {
            propagate_taint32_slti(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_SLTIU:
        {
            propagate_taint32_sltiu(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_XORI:
        {
            propagate_taint32_xori(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_ORI:
        {
            propagate_taint32_ori(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_ANDI:
        {
            propagate_taint32_andi(vcpu_idx, rd, rs1, imm);
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
                propagate_taint32_slli(vcpu_idx, rd, rs1, imm);
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
                propagate_taint32_srli(vcpu_idx, rd, rs1, imm);
            }
            else if (is_srai)
            {
                propagate_taint32_srai(vcpu_idx, rd, rs1, imm);
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

/**
 * Dispatch
 */

/***
 * Opcode dispatch (uncompressed instructions)
 ***/

void propagate_taint32__reg_imm_op(unsigned int vcpu_idx, uint32_t instr)
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

    if (rd == 0) {
        // x0 cannot be tainted, and no instruction of this block can articecturally taint the PC.
        return;
    }

    switch(f3)
    {
        case INSTR32_F3_ADDI:
        {
            propagate_taint32_addi(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_SLTI:
        {
            propagate_taint32_slti(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_SLTIU:
        {
            propagate_taint32_sltiu(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_XORI:
        {
            propagate_taint32_xori(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_ORI:
        {
            propagate_taint32_ori(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_ANDI:
        {
            propagate_taint32_andi(vcpu_idx, rd, rs1, imm);
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
                propagate_taint32_slli(vcpu_idx, rd, rs1, imm);
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
                propagate_taint32_srli(vcpu_idx, rd, rs1, imm);
            else if (is_srai)
                propagate_taint32_srai(vcpu_idx, rd, rs1, imm);
            else
                fprintf(stderr, "Malformed instruction, unknown f6/f7 for f3=SRLI_SRAI: 0x%" PRIx32 "\n", instr);

            break;
        }
        default:
        {
            fprintf(stderr, "Unknown reg-imm op f3 for instr: 0x%" PRIx32 "\n", instr);
            break;
        }
    }
}

void propagate_taint32__reg_reg_op(unsigned int vcpu_idx, uint32_t instr)
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
            propagate_taint32_add(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_SUB)
            propagate_taint32_sub(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_MUL)
            propagate_taint32_mul(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=ADD_SUB_MUL: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_SLL_MULH:
    {
        if (f7 == INSTR32_F7_SLL)
            propagate_taint32_sll(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_MULH)
            propagate_taint32_mul(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLL_MULH: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_SLT_MULHSU:
    {
        if (f7 == INSTR32_F7_SLT)
            propagate_taint32_slt(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_MULHSU)
            propagate_taint32_mul(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLT_MULHSU: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_SLTU_MULHU:
    {
        if (f7 == INSTR32_F7_SLTU)
            propagate_taint32_sltu(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_MULHU)
            propagate_taint32_mul(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLTU_MULHU: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_XOR_DIV:
    {
        if (f7 == INSTR32_F7_XOR)
            propagate_taint32_xor(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_DIV)
            propagate_taint32_mul_div(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=XOR_DIV: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_SRL_SRA_DIVU:
    {
        if (f7 == INSTR32_F7_SRL)
            propagate_taint32_srl(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_SRA)
            propagate_taint32_sra(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_DIVU)
            propagate_taint32_mul_div(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=SRL_SRA_DIVU: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_OR_REM:
    {
        if (f7 == INSTR32_F7_OR)
            propagate_taint32_or(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_REM)
            propagate_taint32_mul_div(vcpu_idx, rd, rs1, rs2);
        else
            fprintf(stderr, "Malformed instruction, unknown f7 for f3=OR_REM: 0x%" PRIx32 "\n", instr);
        break;
    }
    case INSTR32_F3_AND_REMU:
    {
        if (f7 == INSTR32_F7_AND)
            propagate_taint32_and(vcpu_idx, rd, rs1, rs2);
        else if (f7 == INSTR32_F7_REMU)
            propagate_taint32_mul_div(vcpu_idx, rd, rs1, rs2);
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
 * Opcode dispatch (uncompressed instructions, wordsize instructions -- RV64I only).
 ***/

void propagate_taint32__reg_imm_op32(unsigned int vcpu_idx, uint32_t instr)
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
            propagate_taint32_addiw(vcpu_idx, rd, rs1, imm);
            break;
        }
        case INSTR32_F3_SLLIW:
        {
            if (f7 == INSTR32_F7_SLLIW)
                propagate_taint32_slliw(vcpu_idx, rd, rs1, shamt);
            else
                fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLLIW: 0x%" PRIx32 "\n", instr);
            break;
        }
        case INSTR32_F3_SRLIW_SRAIW:
        {
            if (f7 == INSTR32_F7_SRLIW)
                propagate_taint32_srliw(vcpu_idx, rd, rs1, shamt);
            else if (f7 == INSTR32_F7_SRAIW)
                propagate_taint32_sraiw(vcpu_idx, rd, rs1, shamt);
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

void propagate_taint32__reg_reg_op32(unsigned int vcpu_idx, uint32_t instr)
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
                propagate_taint32_addw(vcpu_idx, rd, rs1, rs2);
            else if (f7 == INSTR32_F7_SUBW)
                propagate_taint32_subw(vcpu_idx, rd, rs1, rs2);
            else
                fprintf(stderr, "Malformed instruction, unknown f7 for f3=ADDW_SUBW: 0x%" PRIx32 "\n", instr);
            break;
        }
        case INSTR32_F3_SLLW:
        {
            if (f7 == INSTR32_F7_SLLW)
                propagate_taint32_sllw(vcpu_idx, rd, rs1, rs2);
            else
                fprintf(stderr, "Malformed instruction, unknown f7 for f3=SLLW: 0x%" PRIx32 "\n", instr);

            break;
        }
        case INSTR32_F3_SRLW_SRAW:
        {
            if (f7 == INSTR32_F7_SRLW)
                propagate_taint32_srlw(vcpu_idx, rd, rs1, rs2);
            else if (f7 == INSTR32_F7_SRAW)
                propagate_taint32_sraw(vcpu_idx, rd, rs1, rs2);
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