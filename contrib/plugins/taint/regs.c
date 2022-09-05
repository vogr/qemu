#include "regs.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <errno.h>

#include <qemu-plugin.h>

/***
 * Accessing source registers values through the extended QEMU interface
 */
target_ulong get_one_reg_value(unsigned int vcpu_idx, char r)
{
    qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_idx);
    target_ulong values[1];
    int regs[1] = {r};
    qemu_plugin_get_register_values(cs, 1, regs, values);
    return values[0];
}



struct src_regs_values get_src_reg_values(unsigned int vcpu_idx, char rs1, char rs2)
{
    qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_idx);
    target_ulong values[2];
    int regs[2] = {rs1, rs2};
    qemu_plugin_get_register_values(cs, 2, regs, values);

    struct src_regs_values vals = {
        .v1 = values[0],
        .v2 = values[1]
    };

    return vals;
}