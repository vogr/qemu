#pragma once

#include <stdint.h>

#define MASK(N) ((((uint64_t)1) << N) - 1)


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


#define INSTR32_OPCODE_GET_HI(instr) (uint8_t)((instr >> 2) & MASK(5))
#define INSTR32_OPCODE_GET_LO(instr) (uint8_t)(instr & MASK(2))

#define INSTR32_FUNCT3_MASK (MASK(3) << 12)
#define INSTR32_FUNCT7_MASK (MASK(7) << 25)

#define INSTR32_RD_GET(instr)  (uint8_t)((instr >> 7)  & MASK(5))
#define INSTR32_RS1_GET(instr) (uint8_t)((instr >> 15) & MASK(5))
#define INSTR32_RS2_GET(instr) (uint8_t)((instr >> 20) & MASK(5))

#define INSTR32_I_IMM_0_11_GET(instr) ((instr >>  20) & MASK(12))
#define INSTR32_S_IMM_0_4_GET(instr)  ((instr >>  7)  & MASK(5))
#define INSTR32_S_IMM_5_11_GET(instr) ((instr >>  25) & MASK(7))
#define INSTR32_U_IMM_12_31_GET(instr) ((instr >>  12) & MASK(20))

#define INSTR32_S_IMM_0_11_GET(instr) ((INSTR32_S_IMM_5_11_GET(instr) << 5) | INSTR32_S_IMM_0_4_GET(instr))


/** Opcodes for uncompressed 32 bits instructions **/


// see first table in "RV32/64G Instruction Set Listings"
// chapter 24 in spec2019

// opcodes for non-compressed 32 bits instructions
// are 7 bits long and end in 0b11

#define INSTR32_OPCODE_HI_LOAD      0b00000
#define INSTR32_OPCODE_HI_LOAD_FP   0b00001
//custom                            0b00010
#define INSTR32_OPCODE_HI_MISC_MEM  0b00011
#define INSTR32_OPCODE_HI_OP_IMM    0b00100
#define INSTR32_OPCODE_HI_AUIPC     0b00101
#define INSTR32_OPCODE_HI_OP_IMM_32 0b00110
#define INSTR32_OPCODE_HI_STORE     0b01000
#define INSTR32_OPCODE_HI_STORE_FP  0b01001
//custom                            0b01010
#define INSTR32_OPCODE_HI_AMO       0b01011
#define INSTR32_OPCODE_HI_OP        0b01100
#define INSTR32_OPCODE_HI_LUI       0b01101
#define INSTR32_OPCODE_HI_OP_32     0b01110
#define INSTR32_OPCODE_HI_MADD      0b10000
#define INSTR32_OPCODE_HI_MSUB      0b10001
#define INSTR32_OPCODE_HI_NMSUB     0b10010
#define INSTR32_OPCODE_HI_NMADD     0b10011
#define INSTR32_OPCODE_HI_OP_FP     0b10100
//reserved                          0b10101
//custom                            0b10110
#define INSTR32_OPCODE_HI_BRANCH    0b11000
#define INSTR32_OPCODE_HI_JALR      0b11001
//reserved                          0b11010
#define INSTR32_OPCODE_HI_JAL       0b11011
#define INSTR32_OPCODE_HI_SYSTEM    0b11100
//reserved                          0b11101
//custom                            0b11110

/** RV64I decoding **/

// Loads

#define INSTR32_F3_LB  (0b000 << 12)
#define INSTR32_F3_LH  (0b001 << 12)
#define INSTR32_F3_LW  (0b010 << 12)
#define INSTR32_F3_LD  (0b011 << 12)
#define INSTR32_F3_LBU (0b100 << 12)
#define INSTR32_F3_LHU (0b101 << 12)
#define INSTR32_F3_LWU (0b110 << 12)

// Stores


// Register-immediate ops


// Register-register ops

#define INSTR32_F3F7_ADD  ((0b000 << 12) | (0b0000000 << 25))
#define INSTR32_F3F7_SUB  ((0b000 << 12) | (0b0100000 << 25))
#define INSTR32_F3F7_SLL  ((0b001 << 12) | (0b0000000 << 25))
#define INSTR32_F3F7_SLT  ((0b010 << 12) | (0b0000000 << 25))
#define INSTR32_F3F7_SLTU ((0b011 << 12) | (0b0000000 << 25))
#define INSTR32_F3F7_XOR  ((0b100 << 12) | (0b0000000 << 25))
#define INSTR32_F3F7_SRL  ((0b101 << 12) | (0b0000000 << 25))
#define INSTR32_F3F7_SRA  ((0b101 << 12) | (0b0100000 << 25))
#define INSTR32_F3F7_OR   ((0b110 << 12) | (0b0000000 << 25))
#define INSTR32_F3F7_AND  ((0b111 << 12) | (0b0000000 << 25))






/***
 * 32 bits long instructions (uncompressed)
 * 
 * Formats: FIXME
 */

#define INSTR16_OP_MASK MASK(2)
#define INSTR16_FUNCT6_MASK (MASK(6) << 10)
#define INSTR16_FUNCT2_MASK (MASK(2) << 5)

#define INSTR16_OPF2F6_CAND ((0b01) | (0b11 << 5) | (0b100011 << 10))
