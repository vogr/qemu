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
