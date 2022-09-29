#include "common_propagate.h"

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

void propagate_taint_muldiv(unsigned int vcpu_idx, uint32_t instr);
