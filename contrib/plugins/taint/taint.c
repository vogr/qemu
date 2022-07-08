/*
 * Copyright (C) 2022, Valentin Ogier <contact@vogier.fr>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <stdio.h>

#include <sys/mman.h>

#include <glib.h>

#include <qemu-plugin.h>

#include "hmp.h"
#include "params.h"
#include "propagate.h"

#define HMP_UNIX_SOCKET "/tmp/qemu_hmp.sock"


/*
 * Taint tracking plugin.
 *
 * Currently only implemented for RISCV system emulation.
 */

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;




static void vcpu_mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                            uint64_t vaddr, void *userdata)
{

    struct qemu_plugin_hwaddr *hwaddr  = qemu_plugin_get_hwaddr(info, vaddr);
    g_assert(hwaddr != NULL);

    if (qemu_plugin_hwaddr_is_io(hwaddr)) {
        // We don't support tainted IO devices
        return;
    }

    uint64_t phys_addr = qemu_plugin_hwaddr_phys_addr(hwaddr);

    qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_index);
    uint64_t paddr_cs  = qemu_plugin_translate_vaddr(cs, vaddr);

    printf("Memory access at vaddr %" PRIx64 ", paddr_mon %" PRIx64 " paddr_cs %" PRIx64 "\n", vaddr, phys_addr, paddr_cs);


    /*
     * Currently:
     * 1. read the response from QEMU, drop the unused data, copy register representation
     *    in a buffer, then parse the buffer, then do taint propagation
     * 2. Improvement 1: do the parse and taint in another thread so that we can give
     *    back control of main thread to QEMU. E.g. push buffer to a (blocking?) queue
     *    and return. Another thread picks up buffer and processes.
     */ 

    //get_regs_repr(ALL_REGS_STRING_MAX_LEN, all_regs_string);


    // Parse the integer and fp registers (as uint32)
}


// Instr sizes are just 16 or 32, use a uint32 for both 
struct InsnData
{
    char * disas; //FIXME: remove when no longer needed for debug!
    size_t instr_size;
    uint32_t instr;
};

static void vcpu_insn_exec(unsigned int vcpu_index, void *userdata)
{
    struct InsnData * ins_data = (struct InsnData*)userdata;
    //printf("(%x) %s\n", ins_data->instr, ins_data->disas);
    propagate_taint(vcpu_index, ins_data->instr_size, ins_data->instr);
}


/*
 * Translation callback. Instrument the instructions supported
 * by the taint analysis.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n_insns = qemu_plugin_tb_n_insns(tb);

    // Instrument all the memory accesses (READ and WRITES)
    for (size_t i = 0; i < n_insns; i++)
    {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

        void * data_mem = NULL;

        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, data_mem);



        void const * instr_ptr = qemu_plugin_insn_data(insn);
        
        // instruction size in bits
        size_t instr_size = 8 * qemu_plugin_insn_size(insn);

        // FIXME: use g_hash_table and/or g_new (refcount) to keep track
        // of allocated memory.
        
        // Trainling  array 
        struct InsnData * ins_data = malloc(sizeof(struct InsnData));

        // disas: allocated string
        ins_data->disas = qemu_plugin_insn_disas(insn);
        ins_data->instr_size = instr_size;
        
        // read the instruction's bytecode
        switch (instr_size)
        {
            case 16:
            {
                uint16_t * ins16_ptr = (uint16_t*)instr_ptr;
                ins_data->instr = *ins16_ptr;
                break;
            }
            case 32:
            {
                uint32_t * ins32_ptr = (uint32_t*)instr_ptr;
                ins_data->instr = *ins32_ptr;
                break;
            }
            default:
            {
                fprintf(stderr, "ERROR: Unexpected instruction size: %zu\n", instr_size);
                exit(1);
                break;
            }
        }
        

        // "Readonly" regs, but not implemented on QEMU's side...
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                         QEMU_PLUGIN_CB_R_REGS, (void*)ins_data);
    }
}



// free ressources
static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    fprintf(stderr, "Exiting taint tracking plugin.\n");
    close_hmp_socket();
}


QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    
    fprintf(stderr, "Connecting to monitor on unix socket: %s\n", HMP_UNIX_SOCKET);

    open_hmp_socket(HMP_UNIX_SOCKET);

    // allocate memory for the shadow memory
    // noreserve: only allocate a page when we write a taint value
    // FIXME: one bit per location, should extend to set of labels.
    shadow_mem = mmap(NULL, PHYS_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

    return 0;
}


