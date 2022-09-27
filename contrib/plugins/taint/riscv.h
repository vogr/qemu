#pragma once

#include <stdint.h>

#include "xlen.h"

static inline target_ulong MASK(int N)
{
    return (((target_ulong)1) << N) - 1;
}

static inline target_ulong SIGN_EXTEND(target_ulong N, int k)
{
    target_ulong m = ((target_ulong)1) << k;
    target_ulong low_mask = m - 1;
    return (N & low_mask) - (N & m);
}
/***
 * 32 bits long instructions (uncompressed)
 * 
 * Formats:
 * 
 * 
 * - R
 *   [  funct7 (7)   ][ rs2 (5) ][ rs1 (5) ][ funct3 (3) ][  rd      (5) ][ opcode (7) ]
 *
 * - I
 *   [     imm[11:0]      (12)  ][ rs1 (5) ][ funct3 (3) ][  rd      (5) ][ opcode (7) ]
 * 
 * - S
 *   [ imm[11:5] (7) ][ rs2 (5) ][ rs1 (5) ][ funct3 (3) ][ imm[4:0] (5) ][ opcode (7) ]
 * 
 * - B
 *   [ imm[12] | imm[10:5] (7) ][ rs2 (5) ][ rs1 (5) ][ funct3 (3) ][ imm[4:1] | imm[11] (5) ][ opcode (7) ]
 * 

 * - U
 *   [                 imm[31:12]                    (20) ][  rd      (5) ][ opcode (7) ]
 *
 * - J
 *   [ imm[20] |   imm[10:1] | imm[11] | immm[19:12] (20) ][  rd      (5) ][ opcode (7) ]
 * 
 **/


/** Masks **/

#define INSTR32_OPCODE_GET_HI(instr) ((instr >> 2) & MASK(5))
#define INSTR32_OPCODE_GET_LO(instr) (instr & MASK(2))

#define INSTR32_GET_FUNCT3(instr) ((instr >> 12) & MASK(3))
#define INSTR32_GET_FUNCT7(instr) ((instr >> 25) & MASK(7))

#define INSTR32_RD_GET(instr)  ((instr >> 7)  & MASK(5))
#define INSTR32_RS1_GET(instr) ((instr >> 15) & MASK(5))
#define INSTR32_RS2_GET(instr) ((instr >> 20) & MASK(5))

#define INSTR32_I_IMM_0_11_GET(instr) ((instr >>  20) & MASK(12))
#define INSTR32_S_IMM_0_4_GET(instr)  ((instr >>  7)  & MASK(5))
#define INSTR32_S_IMM_5_11_GET(instr) ((instr >>  25) & MASK(7))
#define INSTR32_U_IMM_12_31_GET(instr) ((instr >>  12) & MASK(20))

#define INSTR32_J_IMM_20_GET(instr) ((instr >> 31) & 1)
#define INSTR32_J_IMM_10_1_GET(instr) ((instr >> 21) & MASK(10))
#define INSTR32_J_IMM_11_GET(instr) ((instr >> 20) & 1)
#define INSTR32_J_IMM_19_12_GET(instr) ((instr >> 12) & MASK(8))


static inline uint32_t INSTR32_S_IMM_0_11_GET(uint32_t instr)
{
    uint32_t ret =
        (INSTR32_S_IMM_5_11_GET(instr) << 5) |
        INSTR32_S_IMM_0_4_GET(instr);
    return ret;
}


static inline uint32_t INSTR32_J_IMM_0_20_GET(uint32_t instr)
{
    uint32_t ret = 
        (INSTR32_J_IMM_10_1_GET(instr) << 1) |
        (INSTR32_J_IMM_11_GET(instr) << 11) |
        (INSTR32_J_IMM_19_12_GET(instr) << 12) |
        (INSTR32_J_IMM_20_GET(instr) << 20);
    return ret;
}

#define INSTR32_I_SHAMT_GET_FIVE(instr) ((instr >>  20) & MASK(5))
#define INSTR32_I_SHAMT_GET_SIX(instr) ((instr >>  20) & MASK(6))


/** Opcodes for uncompressed 32 bits instructions **/


// see first table in "RV32/64G Instruction Set Listings"
// chapter 24 in spec2019

// opcodes for non-compressed 32 bits instructions
// are 7 bits long and end in 0b11

enum {
    INSTR32_OPCODE_HI_LOAD     = 0b00000,
    INSTR32_OPCODE_HI_LOAD_FP  = 0b00001,
    //custom                   = 0b00010,
    INSTR32_OPCODE_HI_MISC_MEM = 0b00011,
    INSTR32_OPCODE_HI_OP_IMM   = 0b00100,
    INSTR32_OPCODE_HI_AUIPC    = 0b00101,
    INSTR32_OPCODE_HI_OP_IMM_32= 0b00110,
    INSTR32_OPCODE_HI_STORE    = 0b01000,
    INSTR32_OPCODE_HI_STORE_FP = 0b01001,
    //custom                   = 0b01010,
    INSTR32_OPCODE_HI_AMO      = 0b01011,
    INSTR32_OPCODE_HI_OP       = 0b01100,
    INSTR32_OPCODE_HI_LUI      = 0b01101,
    INSTR32_OPCODE_HI_OP_32    = 0b01110,
    INSTR32_OPCODE_HI_MADD     = 0b10000,
    INSTR32_OPCODE_HI_MSUB     = 0b10001,
    INSTR32_OPCODE_HI_NMSUB    = 0b10010,
    INSTR32_OPCODE_HI_NMADD    = 0b10011,
    INSTR32_OPCODE_HI_OP_FP    = 0b10100,
    //reserved                 = 0b10101,
    //custom                   = 0b10110,
    INSTR32_OPCODE_HI_BRANCH   = 0b11000,
    INSTR32_OPCODE_HI_JALR     = 0b11001,
    //reserved                 = 0b11010,
    INSTR32_OPCODE_HI_JAL      = 0b11011,
    INSTR32_OPCODE_HI_SYSTEM   = 0b11100,
    //reserved                 = 0b11101,
    //custom                   = 0b11110,
};

/** RV32I/RV64I decoding **/

// Loads
enum {
    INSTR32_F3_LB  = 0b000,
    INSTR32_F3_LH  = 0b001,
    INSTR32_F3_LW  = 0b010,
    INSTR32_F3_LD  = 0b011,
    INSTR32_F3_LBU = 0b100,
    INSTR32_F3_LHU = 0b101,
    INSTR32_F3_LWU = 0b110,
};

// Floating point loads
enum {
    INSTR32_F3_FLW = 0b010,
    INSTR32_F3_FLD = 0b011,
};

// Stores
enum {
    INSTR32_F3_SB  = 0b000,
    INSTR32_F3_SH  = 0b001,
    INSTR32_F3_SW  = 0b010,
    INSTR32_F3_SD  = 0b011,
};

// Floating point stores
enum {
    INSTR32_F3_FSW = 0b010,
    INSTR32_F3_FSD = 0b011,
};

// Register-immediate ops
enum {
    INSTR32_F3_ADDI       = 0b000,
    INSTR32_F3_SLTI       = 0b010,
    INSTR32_F3_SLTIU      = 0b011,
    INSTR32_F3_XORI       = 0b100,
    INSTR32_F3_ORI        = 0b110,
    INSTR32_F3_ANDI       = 0b111,
    INSTR32_F3_SLLI__     = 0b001,
    INSTR32_F3_SRLI__SRAI = 0b101,
};


enum {
    INSTR32_F7_SLLI_RV32 = 0b0000000,
    INSTR32_F7_SRLI_RV32 = 0b0000000,
    INSTR32_F7_SRAI_RV32 = 0b0100000,
};

enum {
    INSTR32_F6_SLLI_RV64 = 0b000000,
    INSTR32_F6_SRLI_RV64 = 0b000000,
    INSTR32_F6_SRAI_RV64 = 0b010000,
};


// Register-register ops

enum {
    INSTR32_F3_ADD_SUB_MUL  = 0b000,
    INSTR32_F3_SLL_MULH     = 0b001,
    INSTR32_F3_SLT_MULHSU   = 0b010,
    INSTR32_F3_SLTU_MULHU   = 0b011,
    INSTR32_F3_XOR_DIV      = 0b100,
    INSTR32_F3_SRL_SRA_DIVU = 0b101,
    INSTR32_F3_OR_REM       = 0b110,
    INSTR32_F3_AND_REMU     = 0b111
};

enum {
    INSTR32_F7_ADD  = 0b0000000,
    INSTR32_F7_SUB  = 0b0100000,
    INSTR32_F7_SLL  = 0b0000000,
    INSTR32_F7_SLT  = 0b0000000,
    INSTR32_F7_SLTU = 0b0000000,
    INSTR32_F7_XOR  = 0b0000000,
    INSTR32_F7_SRL  = 0b0000000,
    INSTR32_F7_SRA  = 0b0100000,
    INSTR32_F7_OR   = 0b0000000,
    INSTR32_F7_AND  = 0b0000000,
    // MUL extension
    INSTR32_F7_MUL    = 0b0000001,
    INSTR32_F7_MULH   = 0b0000001,
    INSTR32_F7_MULHSU = 0b0000001,
    INSTR32_F7_MULHU  = 0b0000001,
    INSTR32_F7_DIV    = 0b0000001,
    INSTR32_F7_DIVU   = 0b0000001,
    INSTR32_F7_REM    = 0b0000001,
    INSTR32_F7_REMU   = 0b0000001,
};


// Register-immediate wordsize ops

enum {
    INSTR32_F3_ADDIW = 0b000,
    INSTR32_F3_SLLIW = 0b001,
    INSTR32_F3_SRLIW_SRAIW = 0b101,
};

enum {
    // INSTR32_F7_ADDIW -> no f7, imm[11:0] instead
    INSTR32_F7_SLLIW = 0b0000000,
    INSTR32_F7_SRLIW = 0b0000000,
    INSTR32_F7_SRAIW = 0b0100000,
};

// Register-register wordsize ops

enum {
    INSTR32_F3_ADDW_SUBW = 0b000,
    INSTR32_F3_SLLW = 0b001,
    INSTR32_F3_SRLW_SRAW = 0b101,
};

enum {
    INSTR32_F7_ADDW = 0b0000000,
    INSTR32_F7_SUBW = 0b0100000,
    INSTR32_F7_SLLW = 0b0000000,
    INSTR32_F7_SRLW = 0b0000000,
    INSTR32_F7_SRAW = 0b0100000,
};

/***
 * 16 bits long instructions (compressed)
 * 
 * Formats: FIXME
 */

// Map compressed representation r' (3 bits) to full register repr (5 bits)
// see https://en.wikichip.org/wiki/risc-v/registers
#define REG_OF_COMPRESSED(x) ((uint8_t)x + 8)

#define INSTR16_CIW_RDC_GET(instr) ((instr >>  2) & MASK(3))
#define INSTR16_CIW_IMM_LO_GET(instr) ((instr >>  5) & MASK(2))
#define INSTR16_CIW_IMM_HI_GET(instr) ((instr >>  10) & MASK(3))
#define INSTR16_CIW_IMM_GET(instr) ((instr >>  5) & MASK(8))


#define INSTR16_CL_RDC_GET(instr) ((instr >>  2) & MASK(3))
#define INSTR16_CL_RS1C_GET(instr) ((instr >>  7) & MASK(3))

#define INSTR16_CS_RS1C_GET(instr) ((instr >>  7) & MASK(3))
#define INSTR16_CS_RS2C_GET(instr) ((instr >>  2) & MASK(3))


#define INSTR16_C1_IMM_0_4_GET(instr) ((instr >> 2) & MASK(5))
#define INSTR16_C1_IMM_5_GET(instr) ((instr >> 12) & 1)
#define INSTR16_C1_IMM_GET(instr) (INSTR16_C1_IMM_0_4_GET(instr) | (INSTR16_C1_IMM_5_GET(instr) << 5))

#define INSTR16_C1_RD_GET(instr) ((instr >> 7) & MASK(5))

/** Opcodes for compressed 16 bits instructions **/

// 2 levels of opcodes: inst[1:0] and inst[15:13]

#define INSTR16_OPCODE_GET_HI(instr) ((instr >> 13) & MASK(3))
#define INSTR16_OPCODE_GET_LO(instr) (instr & MASK(2))

// instructions are grouped by LO bits, concatenate as [LO ; HI]
#define INSTR16_OPCODE_GET(instr) ((INSTR16_OPCODE_GET_LO(instr) << 3) | INSTR16_OPCODE_GET_HI(instr))

// instructions differ between RV32 and RV64
enum {
    INSTR16_RV64_OPCODE_ADDI4SPN     = 0b00000,
    INSTR16_RV64_OPCODE_FLD,
    INSTR16_RV64_OPCODE_LW,
    INSTR16_RV64_OPCODE_LD,
    INSTR16_RV64_OPCODE__RESERVED,
    INSTR16_RV64_OPCODE_FSD,
    INSTR16_RV64_OPCODE_SW,
    INSTR16_RV64_OPCODE_SD,
    INSTR16_RV64_OPCODE_ADDI,
    INSTR16_RV64_OPCODE_ADDIW,
    INSTR16_RV64_OPCODE_LI,
    INSTR16_RV64_OPCODE_LUI_ADDI16SP,
    INSTR16_RV64_OPCODE_MISC_ALU, // 01100
    INSTR16_RV64_OPCODE_J,
    INSTR16_RV64_OPCODE_BEQZ,
    INSTR16_RV64_OPCODE_BNEZ,
    INSTR16_RV64_OPCODE_SLLI,
    INSTR16_RV64_OPCODE_FLDSP,
    INSTR16_RV64_OPCODE_LWSP,
    INSTR16_RV64_OPCODE_LDSP,
    INSTR16_RV64_OPCODE_JALR_MV_ADD,
    INSTR16_RV64_OPCODE_FSDSP,
    INSTR16_RV64_OPCODE_SWSP,
    INSTR16_RV64_OPCODE_SDSP,
};



