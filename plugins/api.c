/*
 * QEMU Plugin API
 *
 * This provides the API that is available to the plugins to interact
 * with QEMU. We have to be careful not to expose internal details of
 * how QEMU works so we abstract out things like translation and
 * instructions to anonymous data types:
 *
 *  qemu_plugin_tb
 *  qemu_plugin_insn
 *
 * Which can then be passed back into the API to do additional things.
 * As such all the public functions in here are exported in
 * qemu-plugin.h.
 *
 * The general life-cycle of a plugin is:
 *
 *  - plugin is loaded, public qemu_plugin_install called
 *    - the install func registers callbacks for events
 *    - usually an atexit_cb is registered to dump info at the end
 *  - when a registered event occurs the plugin is called
 *     - some events pass additional info
 *     - during translation the plugin can decide to instrument any
 *       instruction
 *  - when QEMU exits all the registered atexit callbacks are called
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019, Linaro
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "qemu/osdep.h"
#include "qemu/plugin.h"
#include "qemu/log.h"
#include "tcg/tcg.h"
#include "exec/exec-all.h"
#include "exec/ram_addr.h"
#include "disas/disas.h"
#include "plugin.h"
#ifndef CONFIG_USER_ONLY
#include "qemu/plugin-memory.h"
#include "hw/boards.h"
#else
#include "qemu.h"
#ifdef CONFIG_LINUX
#include "loader.h"
#endif
#endif

/* Uninstall and Reset handlers */

void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
    plugin_reset_uninstall(id, cb, false);
}

void qemu_plugin_reset(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
    plugin_reset_uninstall(id, cb, true);
}

/*
 * Plugin Register Functions
 *
 * This allows the plugin to register callbacks for various events
 * during the translation.
 */

void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_INIT, cb);
}

void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_EXIT, cb);
}

void qemu_plugin_register_vcpu_tb_exec_cb(struct qemu_plugin_tb *tb,
                                          qemu_plugin_vcpu_udata_cb_t cb,
                                          enum qemu_plugin_cb_flags flags,
                                          void *udata)
{
    if (!tb->mem_only) {
        plugin_register_dyn_cb__udata(&tb->cbs[PLUGIN_CB_REGULAR],
                                      cb, flags, udata);
    }
}

void qemu_plugin_register_vcpu_tb_exec_inline(struct qemu_plugin_tb *tb,
                                              enum qemu_plugin_op op,
                                              void *ptr, uint64_t imm)
{
    if (!tb->mem_only) {
        plugin_register_inline_op(&tb->cbs[PLUGIN_CB_INLINE], 0, op, ptr, imm);
    }
}

void qemu_plugin_register_vcpu_insn_exec_cb(struct qemu_plugin_insn *insn,
                                            qemu_plugin_vcpu_udata_cb_t cb,
                                            enum qemu_plugin_cb_flags flags,
                                            void *udata)
{
    if (!insn->mem_only) {
        plugin_register_dyn_cb__udata(&insn->cbs[PLUGIN_CB_INSN][PLUGIN_CB_REGULAR],
                                      cb, flags, udata);
    }
}

void qemu_plugin_register_vcpu_insn_exec_inline(struct qemu_plugin_insn *insn,
                                                enum qemu_plugin_op op,
                                                void *ptr, uint64_t imm)
{
    if (!insn->mem_only) {
        plugin_register_inline_op(&insn->cbs[PLUGIN_CB_INSN][PLUGIN_CB_INLINE],
                                  0, op, ptr, imm);
    }
}


/*
 * We always plant memory instrumentation because they don't finalise until
 * after the operation has complete.
 */
void qemu_plugin_register_vcpu_mem_cb(struct qemu_plugin_insn *insn,
                                      qemu_plugin_vcpu_mem_cb_t cb,
                                      enum qemu_plugin_cb_flags flags,
                                      enum qemu_plugin_mem_rw rw,
                                      void *udata)
{
    plugin_register_vcpu_mem_cb(&insn->cbs[PLUGIN_CB_MEM][PLUGIN_CB_REGULAR],
                                    cb, flags, rw, udata);
}

void qemu_plugin_register_vcpu_mem_inline(struct qemu_plugin_insn *insn,
                                          enum qemu_plugin_mem_rw rw,
                                          enum qemu_plugin_op op, void *ptr,
                                          uint64_t imm)
{
    plugin_register_inline_op(&insn->cbs[PLUGIN_CB_MEM][PLUGIN_CB_INLINE],
                              rw, op, ptr, imm);
}

void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t id,
                                           qemu_plugin_vcpu_tb_trans_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_TB_TRANS, cb);
}

void qemu_plugin_register_vcpu_syscall_cb(qemu_plugin_id_t id,
                                          qemu_plugin_vcpu_syscall_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_SYSCALL, cb);
}

void
qemu_plugin_register_vcpu_syscall_ret_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_syscall_ret_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_SYSCALL_RET, cb);
}

/*
 * Plugin Queries
 *
 * These are queries that the plugin can make to gauge information
 * from our opaque data types. We do not want to leak internal details
 * here just information useful to the plugin.
 */

/*
 * Translation block information:
 *
 * A plugin can query the virtual address of the start of the block
 * and the number of instructions in it. It can also get access to
 * each translated instruction.
 */

size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb)
{
    return tb->n;
}

uint64_t qemu_plugin_tb_vaddr(const struct qemu_plugin_tb *tb)
{
    return tb->vaddr;
}

struct qemu_plugin_insn *
qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t idx)
{
    struct qemu_plugin_insn *insn;
    if (unlikely(idx >= tb->n)) {
        return NULL;
    }
    insn = g_ptr_array_index(tb->insns, idx);
    insn->mem_only = tb->mem_only;
    return insn;
}

/*
 * Instruction information
 *
 * These queries allow the plugin to retrieve information about each
 * instruction being translated.
 */

const void *qemu_plugin_insn_data(const struct qemu_plugin_insn *insn)
{
    return insn->data->data;
}

size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *insn)
{
    return insn->data->len;
}

uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn)
{
    return insn->vaddr;
}

void *qemu_plugin_insn_haddr(const struct qemu_plugin_insn *insn)
{
    return insn->haddr;
}

char *qemu_plugin_insn_disas(const struct qemu_plugin_insn *insn)
{
    CPUState *cpu = current_cpu;
    return plugin_disas(cpu, insn->vaddr, insn->data->len);
}

const char *qemu_plugin_insn_symbol(const struct qemu_plugin_insn *insn)
{
    const char *sym = lookup_symbol(insn->vaddr);
    return sym[0] != 0 ? sym : NULL;
}

/*
 * The memory queries allow the plugin to query information about a
 * memory access.
 */

unsigned qemu_plugin_mem_size_shift(qemu_plugin_meminfo_t info)
{
    MemOp op = get_memop(info);
    return op & MO_SIZE;
}

bool qemu_plugin_mem_is_sign_extended(qemu_plugin_meminfo_t info)
{
    MemOp op = get_memop(info);
    return op & MO_SIGN;
}

bool qemu_plugin_mem_is_big_endian(qemu_plugin_meminfo_t info)
{
    MemOp op = get_memop(info);
    return (op & MO_BSWAP) == MO_BE;
}

bool qemu_plugin_mem_is_store(qemu_plugin_meminfo_t info)
{
    return get_plugin_meminfo_rw(info) & QEMU_PLUGIN_MEM_W;
}

/*
 * Virtual Memory queries
 */

#ifdef CONFIG_SOFTMMU
static __thread struct qemu_plugin_hwaddr hwaddr_info;
#endif

struct qemu_plugin_hwaddr *qemu_plugin_get_hwaddr(qemu_plugin_meminfo_t info,
                                                  uint64_t vaddr)
{
#ifdef CONFIG_SOFTMMU
    CPUState *cpu = current_cpu;
    unsigned int mmu_idx = get_mmuidx(info);
    enum qemu_plugin_mem_rw rw = get_plugin_meminfo_rw(info);
    hwaddr_info.is_store = (rw & QEMU_PLUGIN_MEM_W) != 0;

    if (!tlb_plugin_lookup(cpu, vaddr, mmu_idx,
                           hwaddr_info.is_store, &hwaddr_info)) {
        error_report("invalid use of qemu_plugin_get_hwaddr");
        return NULL;
    }

    return &hwaddr_info;
#else
    return NULL;
#endif
}

bool qemu_plugin_hwaddr_is_io(const struct qemu_plugin_hwaddr *haddr)
{
#ifdef CONFIG_SOFTMMU
    return haddr->is_io;
#else
    return false;
#endif
}

uint64_t qemu_plugin_hwaddr_phys_addr(const struct qemu_plugin_hwaddr *haddr)
{
#ifdef CONFIG_SOFTMMU
    if (haddr) {
        if (!haddr->is_io) {
            RAMBlock *block;
            ram_addr_t offset;
            void *hostaddr = haddr->v.ram.hostaddr;

            block = qemu_ram_block_from_host(hostaddr, false, &offset);
            if (!block) {
                error_report("Bad host ram pointer %p", haddr->v.ram.hostaddr);
                abort();
            }

            return block->offset + offset + block->mr->addr;
        } else {
            MemoryRegionSection *mrs = haddr->v.io.section;
            return mrs->offset_within_address_space + haddr->v.io.offset;
        }
    }
#endif
    return 0;
}

const char *qemu_plugin_hwaddr_device_name(const struct qemu_plugin_hwaddr *h)
{
#ifdef CONFIG_SOFTMMU
    if (h && h->is_io) {
        MemoryRegionSection *mrs = h->v.io.section;
        if (!mrs->mr->name) {
            unsigned long maddr = 0xffffffff & (uintptr_t) mrs->mr;
            g_autofree char *temp = g_strdup_printf("anon%08lx", maddr);
            return g_intern_string(temp);
        } else {
            return g_intern_string(mrs->mr->name);
        }
    } else {
        return g_intern_static_string("RAM");
    }
#else
    return g_intern_static_string("Invalid");
#endif
}


uint64_t qemu_plugin_hwaddr_ram_addr(const struct qemu_plugin_hwaddr *haddr)
{
#ifdef CONFIG_SOFTMMU
    if (!haddr->is_io)
    {
        void * ptr = haddr->v.ram.hostaddr;
        ram_addr_t ram_addr = qemu_ram_addr_from_host(ptr);
        if (ram_addr == RAM_ADDR_INVALID) {
            error_report("Bad ram pointer %p", ptr);
            abort();
        }
        return ram_addr;
    }
#endif
    return 0;
}


/*
 * Queries to the number and potential maximum number of vCPUs there
 * will be. This helps the plugin dimension per-vcpu arrays.
 */

#ifndef CONFIG_USER_ONLY
static MachineState * get_ms(void)
{
    return MACHINE(qdev_get_machine());
}
#endif

int qemu_plugin_n_vcpus(void)
{
#ifdef CONFIG_USER_ONLY
    return -1;
#else
    return get_ms()->smp.cpus;
#endif
}

int qemu_plugin_n_max_vcpus(void)
{
#ifdef CONFIG_USER_ONLY
    return -1;
#else
    return get_ms()->smp.max_cpus;
#endif
}

uint64_t qemu_plugin_get_ram_size(void)
{
#ifdef CONFIG_USER_ONLY
    return -1;
#else
    return get_ms()->ram_size;
#endif
}

uint64_t qemu_plugin_get_max_ram_size(void)
{
#ifdef CONFIG_USER_ONLY
    return -1;
#else
    return get_ms()->maxram_size;
#endif
}



/*
 * CPUState and CPUArchState queries
 */


qemu_cpu_state qemu_plugin_get_cpu(int vcpu_idx)
{
    return qemu_get_cpu(vcpu_idx);
}


void qemu_plugin_get_register_values(qemu_cpu_state pcs, size_t n_registers, int * register_ids, void * values)
{
#if TARGET_RISCV
    RISCVCPU *rvcpu = RISCV_CPU(pcs);
    CPURISCVState *env = &rvcpu->env;

    target_ulong * regs = env->gpr;
    target_ulong * dest = (target_ulong*)values;

    for(size_t i = 0 ; i < n_registers ; i++)
    {
        int regid = register_ids[i];
        if (regid < 32)
            dest[i] = regs[regid];
        else if (regid == 32)
            dest[i] = env->pc;
    }

#else
    g_assert_not_reached();
#endif
}

void qemu_plugin_set_register_values(qemu_cpu_state pcs, size_t n_registers, int * register_ids, void * values)
{
// values passed by void* should have target_ulong size
#if TARGET_RISCV
    RISCVCPU *rvcpu = RISCV_CPU(pcs);
    CPURISCVState *env = &rvcpu->env;

    target_ulong * regs = env->gpr;
    target_ulong * src = (target_ulong*)values;

    for(size_t i = 0 ; i < n_registers ; i++)
    {
        int regid = register_ids[i];
        regs[regid] = src[i];
    }

#else
    g_assert_not_reached();
#endif
}

/*
 * qemu_plugin_get_hwaddr is more efficient and provides more information,
 * however, it must be issued immediatly after the corresponding TLB query
 * (ie after the instruction)
 */

uint64_t qemu_plugin_vaddr_to_paddr(qemu_cpu_state _cs, uint64_t _vaddr)
{
#ifndef CONFIG_USER_ONLY
    CPUState * cs = CPU(_cs);
    target_ulong va = (target_ulong)_vaddr;
    hwaddr page_paddr = cpu_get_phys_page_debug(cs, va);
    hwaddr paddr = page_paddr | (va & (TARGET_PAGE_SIZE - 1));
    return paddr;
#else
    return 0;
#endif
}

//FIXME: move header at the top
#include "exec/address-spaces.h"
int qemu_plugin_paddr_to_ram_addr(uint64_t paddr, uint64_t * ram_addr)
{
    uint64_t offset, mr_len;
    RCU_READ_LOCK_GUARD(); // autoptr lock
    MemoryRegion * mr = address_space_translate(&address_space_memory, paddr, &offset, &mr_len, false, MEMTXATTRS_UNSPECIFIED);
    if (!(memory_region_is_ram(mr)))
    {
        return 1;
    }

    (*ram_addr) = memory_region_get_ram_addr(mr) + offset;
    return 0;
}


int qemu_plugin_read_at_paddr(uint64_t paddr, void * buf, size_t size)
{
    MemTxResult txres = address_space_read(&address_space_memory, paddr, MEMTXATTRS_UNSPECIFIED, buf, size);
    return txres;
}

int qemu_plugin_write_at_paddr(uint64_t paddr, void * buf, size_t size)
{
    MemTxResult txres = address_space_write(&address_space_memory, paddr, MEMTXATTRS_UNSPECIFIED, buf, size);
    return txres;
}


/*
 * Plugin output
 */
void qemu_plugin_outs(const char *string)
{
    qemu_log_mask(CPU_LOG_PLUGIN, "%s", string);
}

bool qemu_plugin_bool_parse(const char *name, const char *value, bool *ret)
{
    return name && value && qapi_bool_parse(name, value, ret, NULL);
}

/*
 * Binary path, start and end locations
 */
const char *qemu_plugin_path_to_binary(void)
{
    char *path = NULL;
#ifdef CONFIG_USER_ONLY
    TaskState *ts = (TaskState *) current_cpu->opaque;
    path = g_strdup(ts->bprm->filename);
#endif
    return path;
}

uint64_t qemu_plugin_start_code(void)
{
    uint64_t start = 0;
#ifdef CONFIG_USER_ONLY
    TaskState *ts = (TaskState *) current_cpu->opaque;
    start = ts->info->start_code;
#endif
    return start;
}

uint64_t qemu_plugin_end_code(void)
{
    uint64_t end = 0;
#ifdef CONFIG_USER_ONLY
    TaskState *ts = (TaskState *) current_cpu->opaque;
    end = ts->info->end_code;
#endif
    return end;
}

uint64_t qemu_plugin_entry_code(void)
{
    uint64_t entry = 0;
#ifdef CONFIG_USER_ONLY
    TaskState *ts = (TaskState *) current_cpu->opaque;
    entry = ts->info->entry;
#endif
    return entry;
}
