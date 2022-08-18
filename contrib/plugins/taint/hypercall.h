#pragma once

void init_hypercall_handler(void);
void vcpu_insn_hypercall_cb(unsigned int vcpu_index, void *userdata);

