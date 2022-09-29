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

// NOTE: Floating-point arithmetic tainting is conserative, for example FMADD (r1 x r2) + r3 will be tainted completely if any of the input registers is tainted.

// Prototypes for util functions
static void propagate_taint_load_fp_impl(unsigned int vcpu_idx, uint8_t rd, target_ulong v1, uint64_t offt, target_ulong t1, enum FP_LOAD_TYPE lt);
static void propagate_taint32__load_fp(unsigned int vcpu_idx, uint32_t instr);
static void propagate_taint_store_fp_impl(unsigned int vcpu_idx, uint8_t rd, target_ulong v1, uint64_t offt, target_ulong t1, target_fplong t2, enum FP_STORE_TYPE lt);
static void propagate_taint32__store_fp(unsigned int vcpu_idx, uint32_t instr);
static void propagate_taint32__fp_madd_msub_nmadd_nmsub_impl(unsigned int vcpu_idx, uint8_t rd, target_fplong t1, target_fplong t2, target_fplong t3);
static void propagate_taint32__fp_madd_msub_nmadd_nmsub(unsigned int vcpu_idx, uint32_t instr);
static void propagate_taint32__fp_regop_impl(unsigned int vcpu_idx, uint8_t rd, target_fplong t1, target_fplong t2);
static void propagate_taint32__fp_sqrt_impl(unsigned int vcpu_idx, uint8_t rd, target_fplong t1);
static void propagate_taint32__fp_to_int_impl(unsigned int vcpu_idx, uint8_t rd, target_fplong t1);
static void propagate_taint32__fp_from_int_impl(unsigned int vcpu_idx, uint8_t rd, target_ulong t1);
static void propagate_taint32__fp_cmp_impl(unsigned int vcpu_idx, uint8_t rd, target_fplong t1, target_fplong t2);
static void propagate_taint32__fp_mv_impl(unsigned int vcpu_idx, uint8_t rd, target_fplong t1);

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

/**
 * Opcode dispatch
 */

void propagate_taint32__fp_op(unsigned int vcpu_idx, uint32_t instr)
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
