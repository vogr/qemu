#pragma once

#include <inttypes.h>

//#define TARGET_RISCV64 1

#ifdef TARGET_RISCV64
    #define XLEN 64
    typedef uint64_t target_ulong;
    typedef int64_t target_long;
    #define TARGET_ULONG_MAX UINT64_MAX
    #define PRIxXLEN PRIx64
#else
    #define XLEN 32
    typedef uint32_t target_ulong;
    typedef int32_t target_long;
    #define TARGET_ULONG_MAX UINT32_MAX
    #define PRIxXLEN PRIx32
#endif