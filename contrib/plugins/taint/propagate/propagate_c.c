#include "propagate.h"
#include "propagate_i.h"
#include "propagate_c.h"

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

static void propagate_taint16_caddi4spn(unsigned int vcpu_idx, uint16_t instr)
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

    target_ulong tout = propagate_taint16__add(v1, nzuimm, t1, 0);

    shadow_regs[rd] = tout;
}


static void propagate_taint16_clw(unsigned int vcpu_idx, uint16_t instr)
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

    propagate_taint32_load_impl(vcpu_idx, rd, v1, offset, t1, LOAD_LW);
}

#ifdef TARGET_RISCV64
static void propagate_taint16_cld(unsigned int vcpu_idx, uint16_t instr)
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

    propagate_taint32_load_impl(vcpu_idx, rd, v1, offset, t1, LOAD_LD);
}
#endif

static void propagate_taint16_csw(unsigned int vcpu_idx, uint16_t instr)
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

    propagate_taint32_store_impl(vcpu_idx, vals.v1, vals.v2, offset, t1, t2, STORE_SW);
}

#ifdef TARGET_RISCV64
static void propagate_taint16_csd(unsigned int vcpu_idx, uint16_t instr)
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

    propagate_taint32_store_impl(vcpu_idx, vals.v1, vals.v2, offset, t1, t2, STORE_SD);
}
#endif

static void propagate_taint16_cli(unsigned int vcpu_idx, uint16_t instr)
{
    // writes immediate to rd (!= x0)
    uint8_t rd = INSTR16_C1_RD_GET(instr);
    assert(rd != 0);
    shadow_regs[rd] = 0;

    _DEBUG("Propagate C.LI(?) -> r%" PRIu8 "\n", rd);
    _DEBUG("t%" PRIu8 " = 0x%" PRIxXLEN "\n", rd, 0);


}

static void propagate_taint16_clui_caddi16sp(unsigned int vcpu_idx, uint16_t instr)
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

        target_ulong tout = propagate_taint16__add(v1, nzimm, t1, 0);

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

static void propagate_taint16_cj(unsigned int vcpu_idx, uint16_t instr)
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
        propagate_taint16_caddi4spn(vcpu_idx, instr);
        break;
    }
    case INSTR16_RV64_OPCODE_FLD:
    {
        // FIXME: floating point not supported
        break;
    }
    case INSTR16_RV64_OPCODE_LW:
    {
        propagate_taint16_clw(vcpu_idx, instr);
        break;
    }
#ifdef TARGET_RISCV64
    case INSTR16_RV64_OPCODE_LD:
    {
        propagate_taint16_cld(vcpu_idx, instr);
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
        propagate_taint16_csw(vcpu_idx, instr);
        break;
    }
#ifdef TARGET_RISCV64
    case INSTR16_RV64_OPCODE_SD:
    {
        propagate_taint16_csd(vcpu_idx, instr);
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
        propagate_taint16_cli(vcpu_idx, instr);
        break;
    }
    case INSTR16_RV64_OPCODE_LUI_ADDI16SP:
    {
        propagate_taint16_clui_caddi16sp(vcpu_idx, instr);
        break;
    }
    case INSTR16_RV64_OPCODE_J:
    {
        propagate_taint16_cj(vcpu_idx, instr);
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