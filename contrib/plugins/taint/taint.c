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

#include "params.h"
#include "propagate.h"


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

    /*
    if (qemu_plugin_hwaddr_is_io(hwaddr)) {
        // We don't support tainted IO devices
        return;
    }
    */

    uint64_t paddr_meminfo = qemu_plugin_hwaddr_phys_addr(hwaddr);
    uint64_t ram_addr_meminfo = qemu_plugin_hwaddr_ram_addr(hwaddr);

    qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_index);
    uint64_t paddr_cs  = qemu_plugin_vaddr_to_paddr(cs, vaddr);
    uint64_t ram_addr_cs = qemu_plugin_paddr_to_ram_addr(paddr_cs);
    if (qemu_plugin_mem_is_store(info))
    {
        printf("Store");
    }
    else
    {
        printf("Load");
    }
    printf(" at vaddr %" PRIx64 "\n", vaddr);
    printf(" -> meminfo: paddr = %" PRIx64 " ram_addr= %" PRIx64 "\n", paddr_meminfo, ram_addr_meminfo);
    printf(" -> cs/as:   paddr = %" PRIx64 " ram_addr= %" PRIx64 "\n", paddr_cs, ram_addr_cs);
    printf(" |- logsize=%d sign_extended=%d  big_endian=%d\n",
         qemu_plugin_mem_size_shift(info),
         qemu_plugin_mem_is_sign_extended(info),
         qemu_plugin_mem_is_big_endian(info)
        );

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
    printf("(%x) %s\n", ins_data->instr, ins_data->disas);
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
        // instr is little endian, the type aliasing works if the host machine
        // also uses little-endian integers!
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
}


QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    
    // allocate memory for the shadow memory
    // noreserve: only allocate a page when we write a taint value
    // FIXME: one bit per location, should extend to set of labels.

    uint64_t ram_size = qemu_plugin_get_ram_size();
    uint64_t max_ram_size = qemu_plugin_get_max_ram_size();
    fprintf(stderr, "Reserving shadow memory for ram size %" PRIu64 "B (max is %" PRIu64 "B)\n", ram_size, max_ram_size);
    shadow_mem = mmap(NULL, ram_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

    return 0;
}


