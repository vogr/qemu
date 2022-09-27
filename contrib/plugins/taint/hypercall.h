#pragma once

void init_hypercall_handler(void);
void vcpu_insn_hypercall_textbased_cb(unsigned int vcpu_index, void *userdata);
void vcpu_insn_hypercall_taintdoubleword_cb(unsigned int vcpu_index, void *userdata);
void vcpu_insn_hypercall_taintfullreg_cb(unsigned int vcpu_index, void *userdata);
