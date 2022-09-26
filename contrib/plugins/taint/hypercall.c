#include "hypercall.h"

#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>

#include <qemu-plugin.h>

#include <msgpack.h>

#include "taint_requests.h"
#include "logging.h"
#include "xlen.h"

static msgpack_unpacker unp = {0};

static msgpack_sbuffer packing_sbuf = {0};
static msgpack_packer pk = {0};

void init_hypercall_handler(void)
{
    if(! msgpack_unpacker_init(&unp, MSGPACK_UNPACKER_INIT_BUFFER_SIZE))
    {
        fprintf(stderr, "MsgPack: Error on unpacker init.");
        exit(1);
    }

    msgpack_packer_init(&pk, &packing_sbuf, msgpack_sbuffer_write);
}

void vcpu_insn_hypercall_textbased_cb(unsigned int vcpu_index, void *userdata)
{
    // the guest has requested the execution of a hypervisor function
    // using the signal instruction
    //     addi zero, zero, 0x421
    // The guest allocates a buffer which will contain the command,
    // and to which the host will write the reply. The guest passes
    // the following parameters:
    //  - the virtual address of the buffer containing the command is in a0
    //  - the size of the command in a1
    //  - the virtual address of the destination buffer is in a2 (or 0)
    //  - the allocated size of the destination buffer in a3
    // The host will return 
    // - the size of the reply in a4
    // NOTE: the caller is allowed to use the input buffer as an output buffer

    _DEBUG("Text-based hypercall requested!");

    qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_index);
    int regs[4] = {10, 11, 12, 13};
    target_ulong values[4];
    qemu_plugin_get_register_values(cs, 4, regs, values);

    target_ulong cmdbuf_vaddr = values[0];
    target_ulong cmd_size = values[1];
    target_ulong repbuf_vaddr = values[2];
    target_ulong repbuf_size = values[3];

    uint64_t cmdbuf_paddr = qemu_plugin_vaddr_to_paddr(cs, cmdbuf_vaddr);

    // Note: we don't read directly through a pointer to handle non-matching endianess
    // between host and guest. This does not add a copy as we can read
    // directly into msgpack's unpacker buffer.

    // reserve space for unpacking
    size_t cur_capacity = msgpack_unpacker_buffer_capacity(&unp);

    _DEBUG("unpack_buf capacity = %zu, needs at least %zu\n", cur_capacity, cmd_size);
    if (cur_capacity < cmd_size)
    {
        fprintf(stderr, "MsgPack: extend hypercall unpacker buffer size.\n");
        // Buffer capacity is low ! Extend it before next read
        if(! msgpack_unpacker_reserve_buffer(&unp, cmd_size))
        {
            fprintf(stderr, "MsgPack: error when extending hypercall unpacker buffer size.\n");
            exit(1);
        }
    }

    // reclaim space for reply
    msgpack_sbuffer_clear(&packing_sbuf);

    _DEBUG("Reading the command at vaddr=%" PRIx64 " paddr=%" PRIx64 "\n", cmdbuf_vaddr, cmdbuf_paddr);
    if(qemu_plugin_read_at_paddr(cmdbuf_paddr, msgpack_unpacker_buffer(&unp), cmd_size))
    {
        fprintf(stderr, "Failed to read hypercall command at paddr 0x%" PRIx64 "\n", cmdbuf_paddr);
        return;
    }
    msgpack_unpacker_buffer_consumed(&unp, cmd_size);



    int cmd_read = 0;
    do
    {
        cmd_read = taint_cmd_process_cmd_block(&unp, &pk);
    } while (cmd_read > 0);
    
    if (cmd_read < 0)
    {
        // The handler returned with an error
        fprintf(stderr, "The cmd handler returned with an error, abort hypercall.");
        return;
    }

    // all the availabe objects have been processed, 
    // the command executed and the replies written
    // to the packer. Write to the buffer.
    // If the buffer is too small, do not copy

    uint64_t outsize = 0;
    if((repbuf_vaddr != 0) && (packing_sbuf.size <= repbuf_size))
    {
        uint64_t repbuf_paddr = qemu_plugin_vaddr_to_paddr(cs, repbuf_vaddr);

        // copy reply to buffer
        qemu_plugin_write_at_paddr(repbuf_paddr, packing_sbuf.data, packing_sbuf.size);
        outsize = packing_sbuf.size;
    }

    assert(outsize < TARGET_ULONG_MAX);

    // write reply size to a4
    int outregs[1] = {14};
    // values passed by void* should have target_ulong size
    target_ulong outval[1] = { (target_ulong) outsize};
    qemu_plugin_set_register_values(cs, 1, outregs, outval);
}

void vcpu_insn_hypercall_taintsingleword_cb(unsigned int vcpu_index, void *regid_ptr)
{
    // the guest has requested the execution of a hypervisor function
    // using the signal instruction
    //     addi zero, zero, N for 0x480 <= N <= 0x49F.
    // The guest requests for a physical memory word to be tainted. This physical memory word is pointed to by register x{N-0x480}
    // The regid variable is a pointer to an uint32_t that contains N-0x480

    _DEBUG("Taint single word hypercall requested!");

    uint32_t regid = *(uint32_t*)regid_ptr;
    uint64_t target_paddr;

    if (regid == 0) {
        // The RISC-V register x0 always contains the value 0.
        target_paddr = 0;
    } else {
        qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_index);
        int regs[1] = {regid};
        target_ulong values[1];
        qemu_plugin_get_register_values(cs, 4, regs, values);
        target_paddr = values[0];
    }
    _DEBUG("Hypercall will taint address: %llx", target_paddr);

    struct set_taint_range_params strp;
    strp.start  = target_paddr;
    strp.length = 4;
    strp.t8     = 0xff;

    taint_paddr_range_explicit(strp);

    _DEBUG("Taint single word hypercall requested!");
}
