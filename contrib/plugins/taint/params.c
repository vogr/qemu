#include "params.h"

#include "hypernotify.h"

uint8_t * shadow_mem = 0;
size_t shadow_mem_size = 0;

// 32 general-purpose registers
target_ulong shadow_regs[32] = {0};
target_ulong shadow_fpregs[32] = {0};
target_ulong shadow_pc = 0;

// To make the PC tainted.
void taint_pc(int vcpu_idx) {
    int should_send_notif = !shadow_pc;

    // Taint the PC.
    shadow_pc = -1ULL;

    // Send a notification saying that the PC is becoming tainted.
    if (should_send_notif) {
        struct HypernotifyData *hndata = malloc(sizeof(struct HypernotifyData));;
        hndata->id = HN_ID_PC_BECOMES_TAINTED;
        vcpu_insn_hypernotify_cb(vcpu_idx, (void*)hndata);
    }
}
// To read whether the PC is tainted.
target_ulong get_pc_taint() {
    return shadow_pc;
}
