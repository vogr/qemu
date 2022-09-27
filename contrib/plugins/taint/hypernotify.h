#pragma once

/*
 * A mix of hypercall and out-of-process taint functionnalities:
 * on a specific instruction, the execution stops and an external
 * process is notified over the taint monitor socket. The external
 * process can interract with QEMU and with the taint plugin using
 * the sockets already made available (the QMP socket and the taint
 * monitor), then asks QEMU to resume excecution.
 */
#include <qemu-plugin.h>

#define HN_ID_GP 0 // General purpose / debug notif
#define HN_ID_PC_BECOMES_TAINTED 1 // PC becomes tainted

struct HypernotifyData
{
    int id;
};

void vcpu_insn_hypernotify_cb(unsigned int vcpu_index, void *userdata);

void init_hypernotify_handler(void);

void monitor_wait_for_resume_command(void);