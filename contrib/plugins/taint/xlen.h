#pragma once

#include <assert.h>
#include <inttypes.h>

static_assert(RISCV_XLEN == 64 || RISCV_XLEN == 32, "RISCV_XLEN must be defined to be equal to 32 or 64!");

#ifndef RISCV_XLEN
#define RISCV_XLEN 64
#endif

#if RISCV_XLEN == 64
    #define TARGET_RISCV64 1
    #define XLEN 64
    typedef uint64_t target_ulong;
    typedef int64_t target_long;
    #define TARGET_ULONG_MAX UINT64_MAX
    #define PRIxXLEN PRIx64
    #define SHIFTS_SHAMT_SIZE 6
#elif RISCV_XLEN == 32
    #define TARGET_RISCV32 1
    #define XLEN 32
    typedef uint32_t target_ulong;
    typedef int32_t target_long;
    #define TARGET_ULONG_MAX UINT32_MAX
    #define PRIxXLEN PRIx32
    #define SHIFTS_SHAMT_SIZE 5
#endif