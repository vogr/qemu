/*
 * Copyright (C) 2022, Valentin Ogier <contact@vogier.fr>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <pthread.h>

#include <qemu-plugin.h>

#include "hypercall.h"
#include "hypernotify.h"
#include "monitor.h"
#include "params.h"
#include "propagate.h"
#include "logging.h"

/*
 * Taint tracking plugin.
 *
 * Currently only implemented for RISCV system emulation.
 */

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;


pthread_t taint_monitor_thread = {0};

#ifdef TAINT_DEBUG_MEM_ACCESSES
static void vcpu_mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                            uint64_t vaddr, void *userdata)
{

    struct qemu_plugin_hwaddr *hwaddr  = qemu_plugin_get_hwaddr(info, vaddr);
    assert(hwaddr != NULL);



    uint64_t paddr_meminfo = qemu_plugin_hwaddr_phys_addr(hwaddr);
    uint64_t ram_addr_meminfo = qemu_plugin_hwaddr_ram_addr(hwaddr);
    

    qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_index);
    uint64_t paddr_cs  = qemu_plugin_vaddr_to_paddr(cs, vaddr);
    uint64_t ram_addr_cs = 0;
    if(qemu_plugin_paddr_to_ram_addr(paddr_cs, &ram_addr_cs))
    {

    }

    if (qemu_plugin_mem_is_store(info))
    {
        _DEBUG("Store");
    }
    else
    {
        _DEBUG("Load");
    }
    _DEBUG(" at vaddr 0x%" PRIx64 "\n", vaddr);

    if (qemu_plugin_hwaddr_is_io(hwaddr)) {
        // We don't support tainted IO devices
        _DEBUG("-> to MMIO !!\n")
    }

    _DEBUG(" -> meminfo: paddr = 0x%" PRIx64 " ram_addr= 0x%" PRIx64 "\n", paddr_meminfo, ram_addr_meminfo);
    _DEBUG(" -> cs/as:   paddr = 0x%" PRIx64 " ram_addr= 0x%" PRIx64 "\n", paddr_cs, ram_addr_cs);
    _DEBUG(" |- logsize=%d sign_extended=%d  big_endian=%d\n",
         qemu_plugin_mem_size_shift(info),
         qemu_plugin_mem_is_sign_extended(info),
         qemu_plugin_mem_is_big_endian(info)
        );
}
#endif

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
    //_DEBUG("%s\n", ins_data->disas);
    propagate_taint(vcpu_index, ins_data->instr_size, ins_data->instr);
}


/*
 * Translation callback. Instrument the instructions supported
 * by the taint analysis.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n_insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < n_insns; i++)
    {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

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
                uint16_t ins16 = 0;
                memcpy(&ins16, instr_ptr, 2);
                ins_data->instr = ins16;
                break;
            }
            case 32:
            {
                uint32_t ins32 = 0;
                memcpy(&ins32, instr_ptr, 4);
                ins_data->instr = ins32;
                break;
            }
            default:
            {
                fprintf(stderr, "ERROR: Unexpected instruction size: %zu\n", instr_size);
                exit(1);
                break;
            }
        }

        // Detect hypercalls, instrument them with the hypercall callback instead
        // of the taint propagation callback
        if (ins_data->instr == 0x42100013)
        {
            // the instruction is "addi zero, zero, 0x421", this is the hypercall signal
            qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_hypercall_cb,
                QEMU_PLUGIN_CB_R_REGS, (void*)ins_data);

        }
        else if ((ins_data->instr & 0xf00fffff) == 0x10000013)
        {
            // the instruction is "addi zero, zero, 0x1vv"
            // where vv is a two digit arbitrary number
            // this is the hypernotify signal
            int id = (ins_data->instr >> 20) & 0xff;

            struct HypernotifyData * hndata = malloc(sizeof(struct HypernotifyData));
            hndata->id = id;

            qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_hypernotify_cb,
                    QEMU_PLUGIN_CB_R_REGS, (void*)hndata); 
        }
        else
        {
#ifdef TAINT_DEBUG_MEM_ACCESSES
            void * data_mem = NULL;
            // Instrument all the memory accesses (READ and WRITES)
            qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access,
                                            QEMU_PLUGIN_CB_NO_REGS,
                                            QEMU_PLUGIN_MEM_RW, data_mem);
#endif
            // "Readonly" regs, but not implemented on QEMU's side...
            qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                            QEMU_PLUGIN_CB_R_REGS, (void*)ins_data);
        }
    }
}



// free ressources
static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    fprintf(stderr, "Exiting taint tracking plugin.\n");

#ifndef NDEBUG
    taint_logging_stop();
#endif
}


QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
#ifndef NDEBUG
    taint_logging_init();
#endif

    /* initialize shadow state */
    // allocate memory for the shadow memory
    // noreserve: only allocate a page when we write a taint value
    // FIXME: one bit per location, should extend to set of labels.
    uint64_t ram_size = qemu_plugin_get_ram_size();
    uint64_t max_ram_size = qemu_plugin_get_max_ram_size();
    fprintf(stderr, "Reserving shadow memory for ram size %" PRIu64 "B (max is %" PRIu64 "B)\n", ram_size, max_ram_size);
    
    // RAM size + ROM size
    shadow_mem_size = ram_size + (0xf000 - 0x1000);
    shadow_mem = mmap(NULL, shadow_mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

    // enable taint monitor: start socket, connect peer, start processing commands
    static char taintmon_path[] = "taint_monitor.sock";
    int ret = pthread_create(&taint_monitor_thread, NULL, taint_monitor_loop_pthread, (void *)taintmon_path);
    if (ret)
    {
        errno = ret;
        perror("Error starting taint monitor thread:");
        exit(1);
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    
    init_hypercall_handler();
    init_hypernotify_handler();



    // Block until peer has sent resume command.
    // In particular, the peer is connected and all its taint request
    // have been processed.
    // NOTE: "resume-recvd" can be set before we reach this function
    // call, it will then return immediately
    _DEBUG("MAIN: Waiting for resume command...\n");
    monitor_wait_for_resume_command();

    return 0;
}


