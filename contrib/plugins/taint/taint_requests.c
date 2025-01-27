#include "taint_requests.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <qemu-plugin.h>

#include "logging.h"
#include "params.h"
#include "monitor_lock.h"

static int pack_ok(msgpack_packer * pk)
{
    // Append reply to the buffer
    msgpack_pack_array(pk, 1); // 1 pair

    // error code
    msgpack_pack_int64(pk, 0);

    return 0;
}

static int parseSetTaintPaddrRangeCmd(msgpack_object_array cmd_arr, struct set_taint_range_params * p)
{
    if(cmd_arr.size != 4)
        return 1;

    msgpack_object p1 = cmd_arr.ptr[1];
    if(p1.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
        return 1;
    p->start = p1.via.u64;

    msgpack_object p2 = cmd_arr.ptr[2];
    if(p2.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
        return 1;
    p->length = p2.via.u64;

    msgpack_object p3 = cmd_arr.ptr[3];
    if(p3.type != MSGPACK_OBJECT_BIN)
        return 1;
    msgpack_object_bin t8_bin = p3.via.bin;
    if (t8_bin.size != 1)
        return 1;
    memcpy(&(p->t8), t8_bin.ptr, 1);

    return 0;
}

static int doTaintPaddrRange(msgpack_packer * pk, struct set_taint_range_params p)
{

    fprintf(stderr, "doTaintPaddrRange(0x%" PRIx64 ", %" PRIu64 ", 0x%" PRIx8")\n", p.start, p.length, p.t8);

    uint64_t start_r = 0;
    qemu_plugin_paddr_to_ram_addr(p.start, &start_r);

    memset(shadow_mem + start_r, p.t8, p.length);

    pack_ok(pk);

    return 0;
}

// This function is called typically due to hypercalls 0x480-0x49F, where no command is provided explicitly.
int taint_paddr_range_explicit(struct set_taint_range_params p)
{
    fprintf(stderr, "taint_paddr_range_explicit(0x%" PRIx64 ", %" PRIu64 ", 0x%" PRIx8")\n", p.start, p.length, p.t8);

    uint64_t start_r = 0;
    qemu_plugin_paddr_to_ram_addr(p.start, &start_r);

    memset(shadow_mem + start_r, p.t8, p.length);

    return 0;
}


struct get_taint_range_params
{
    uint64_t start;
    uint64_t length;
    char t8;
};

static int parseGetTaintPaddrRangeCmd(msgpack_object_array cmd_arr, struct get_taint_range_params * p)
{
    if(cmd_arr.size != 3)
        return 1;

    msgpack_object p1 = cmd_arr.ptr[1];
    if(p1.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
        return 1;
    p->start = p1.via.u64;

    msgpack_object p2 = cmd_arr.ptr[2];
    if(p2.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
        return 1;
    p->length = p2.via.u64;

    return 0;
}


static int doGetTaintPaddrRange(msgpack_packer * pk, struct get_taint_range_params p)
{
    fprintf(stderr, "doGetTaintPaddrRange(0x%" PRIx64 ", %" PRIu64 ")\n", p.start, p.length);

    uint64_t start_r = 0;
    qemu_plugin_paddr_to_ram_addr(p.start, &start_r);


    // Append reply to the buffer
    msgpack_pack_array(pk, 2);

    // error code
    msgpack_pack_int64(pk, 0);

    // Value
    msgpack_pack_bin(pk, p.length);
    msgpack_pack_bin_body(pk, shadow_mem + start_r, p.length);

    return 0;
}

struct set_taint_reg_params
{
    uint64_t reg;
    target_ulong t; // xlen bits
};

static int parseSetTaintRegCmd(msgpack_object_array cmd_arr, struct set_taint_reg_params * p)
{
    if(cmd_arr.size != 3)
        return 1;

    msgpack_object p1 = cmd_arr.ptr[1];
    if(p1.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
        return 1;
    p->reg = p1.via.u64;

    msgpack_object p2 = cmd_arr.ptr[2];
    if(p2.type != MSGPACK_OBJECT_BIN)
        return 1;
    msgpack_object_bin t64_bin = p2.via.bin;
    if(t64_bin.size != sizeof(target_ulong))
        return 1;
    memcpy(&(p->t), t64_bin.ptr, sizeof(target_ulong));

    return 0;
}

static int doTaintReg(msgpack_packer * pk, struct set_taint_reg_params p)
{
    fprintf(stderr, "doTaintReg(%" PRIu64 ", %" PRIxXLEN ")\n", p.reg, p.t);

    // FIXME: locking! Or really? Could also say:
    // accessing during execution is UB
    shadow_regs[p.reg] = p.t;

    pack_ok(pk);

    return 0;
}

struct get_taint_reg_params
{
    uint64_t reg;
};

static int parseGetTaintRegCmd(msgpack_object_array cmd_arr, struct get_taint_reg_params * p)
{
    if(cmd_arr.size != 2)
        return 1;

    msgpack_object p1 = cmd_arr.ptr[1];
    if(p1.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
        return 1;
    p->reg = p1.via.u64;

    return 0;
}


static int doGetTaintReg(msgpack_packer * pk, struct get_taint_reg_params p)
{
    fprintf(stderr, "doGetTaintReg(%" PRIu64 ")\n", p.reg);

    target_ulong t = shadow_regs[p.reg];


    // Append reply to the buffer
    msgpack_pack_array(pk, 2);

    // error code
    msgpack_pack_int64(pk, 0);

    // taint
    msgpack_pack_bin(pk, sizeof(target_ulong));
    msgpack_pack_bin_body(pk, &t, sizeof(target_ulong));

    return 0;
}

static int doGetPCTaint(msgpack_packer * pk)
{
    fprintf(stderr, "is_pc_tainted()\n");

    // Append reply to the buffer
    msgpack_pack_array(pk, 2);

    // error code
    msgpack_pack_int64(pk, 0);

    // taint
    msgpack_pack_bin(pk, sizeof(target_ulong));
    target_ulong shadow_pc = get_pc_taint();
    msgpack_pack_bin_body(pk, &shadow_pc, sizeof(target_ulong));

    return 0;
}


struct get_regs_params
{
    int * regs;
    size_t nregs;
    unsigned int vcpu_idx;
};

static int parseGetRegsCmd(msgpack_object_array cmd_arr, struct get_regs_params * p)
{
    if(cmd_arr.size != 3)
        return 1;
    
    msgpack_object p1 = cmd_arr.ptr[1];
    if(p1.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
        return 1;
    p->vcpu_idx = p1.via.u64;

    msgpack_object p2 = cmd_arr.ptr[2];
    if(p2.type != MSGPACK_OBJECT_ARRAY)
        return 1;
    msgpack_object_array regs = p2.via.array;

    int * regs2 = malloc(regs.size * sizeof(int));

    for(int i = 0 ; i < regs.size ; i++)
    {
        msgpack_object r = regs.ptr[i];
        if (r.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
        {
            return 1;
        }
        regs2[i] = r.via.u64;
    }

    p->nregs = regs.size;
    p->regs = regs2;

    return 0;
}

static void destroyGetRegsParams(struct get_regs_params * p)
{
    free(p->regs);
    p->regs = NULL;
}

static int doGetRegs(msgpack_packer * pk, struct get_regs_params p)
{
    fprintf(stderr, "doGetReg(%u, [", p.vcpu_idx);
    
    for (int i = 0 ; i < p.nregs ; i++)
    {
        fprintf(stderr, "%d", p.regs[i]);
        if (i < p.nregs - 1) fprintf(stderr, ",");
    }
    fprintf(stderr, "])");

    target_ulong * v = malloc(p.nregs * sizeof(target_ulong));

    qemu_cpu_state cs = qemu_plugin_get_cpu(p.vcpu_idx);
    qemu_plugin_get_register_values(cs, p.nregs, p.regs, v);

    // Append reply to the buffer
    msgpack_pack_array(pk, 2);

    // error code
    msgpack_pack_int64(pk, 0);

    // taint
    msgpack_pack_array(pk, p.nregs);
    for (int i = 0 ; i < p.nregs ; i++)
    {
        msgpack_pack_bin(pk, sizeof(target_ulong));
        msgpack_pack_bin_body(pk, &v[i], sizeof(target_ulong));
    }

    free(v);

    return 0;
}

// no params!
struct resume_params
{
    int _empty;
};

static int parseResumeCmd(msgpack_object_array cmd_arr, struct resume_params * p)
{
    if(cmd_arr.size != 1)
        return 1;

    return 0;
}

static int doResume(msgpack_packer * pk, struct resume_params p)
{
    fprintf(stderr, "resume()\n");

    // signal to the main thread that it can resume execution
    monitor_resume_recvd = true;
    pthread_cond_signal(&monitor_resume_recvd_cv);

    pack_ok(pk);

    return 0;
}



#define CMD_CMP(cmd, str) \
    ((sizeof(str) - 1 == cmd.size) && ((memcmp(cmd.ptr, str, sizeof(str) - 1) == 0)))



static int taintmon_dispatcher(msgpack_object_array cmd_arr, msgpack_packer * pk)
{
    // Parse the array into command and arguments
    // Write the reply to packer pk

    msgpack_object_str cmd = {0};

    if(cmd_arr.size >= 1)
    {
        msgpack_object param1 = cmd_arr.ptr[0];
        if (param1.type == MSGPACK_OBJECT_STR)
        {
            cmd = param1.via.str;
        }
    }

    // Now dispatch
    int ret;
    if (CMD_CMP(cmd, "set-taint-range"))
    {
        struct set_taint_range_params p = {0};
        if (parseSetTaintPaddrRangeCmd(cmd_arr, &p))
            ret = 1;
        else
            ret = doTaintPaddrRange(pk, p);
    }
    else if (CMD_CMP(cmd, "get-taint-range"))
    {
        struct get_taint_range_params p = {0};
        if (parseGetTaintPaddrRangeCmd(cmd_arr, &p))
            ret = 1;
        else
            ret = doGetTaintPaddrRange(pk, p);
    }
    else if (CMD_CMP(cmd, "set-taint-reg"))
    {
        struct set_taint_reg_params p = {0};
        if (parseSetTaintRegCmd(cmd_arr, &p))
            ret = 1;
        else
            ret = doTaintReg(pk, p);
    }
    else if (CMD_CMP(cmd, "get-taint-reg"))
    {

        struct get_taint_reg_params p = {0};
        if (parseGetTaintRegCmd(cmd_arr, &p))
            ret = 1;
        else
            ret = doGetTaintReg(pk, p);
    }
    else if (CMD_CMP(cmd, "get-pc-taint"))
    {
        ret = doGetPCTaint(pk);
    }
    else if (CMD_CMP(cmd, "get-regs"))
    {
        struct get_regs_params p = {0};
        if (parseGetRegsCmd(cmd_arr, &p))
            ret = 1;
        else
        {
            ret = doGetRegs(pk, p);
            destroyGetRegsParams(&p);
        }
    }
    else if (CMD_CMP(cmd, "resume"))
    {
        // notify main thread that resumption can happen
        // this command should follow a "notify" sent by the main
        // thread to the controller upon
        struct resume_params p = {0};
        if (parseResumeCmd(cmd_arr, &p))
            ret = 1;
        else
            ret = doResume(pk, p);
    }
    else
    {
        fprintf(stderr, "Warning: skipping request, invalid or inexistant command in array.\n");
        ret = 1;
    }

    return ret;
}

static int obj_is_list_of_cmds(msgpack_object obj)
{
    // -1: malformed
    //  0: single command
    //  1: list of commands
    if(obj.type != MSGPACK_OBJECT_ARRAY)
    {
        return -1;
    }

    msgpack_object_array outer = obj.via.array;
    if (outer.size < 1)
    {
        return -1;
    }

    msgpack_object inner = outer.ptr[0];
    return (inner.type == MSGPACK_OBJECT_ARRAY);
}

static int taintmon_req_handler(msgpack_object obj, msgpack_packer * pk)
{
#ifndef NDEBUG
    _DEBUG("MON: Handling command:\n");
    msgpack_object_print(taintlog_fp, obj);
    fprintf(taintlog_fp, "\n");
#endif

    /*
     * The serialized object can either be a command (=a list), or a list
     * of commands (list of lists)
     *
     * Will pack the reply in the packer (by appending, will not empty the
     * packer if it already contains msgpack objects!)
     */

    int is_list_of_cmds = obj_is_list_of_cmds(obj);
    if(is_list_of_cmds == 1)
    {
        msgpack_object_array cmds = obj.via.array;

        // prepare the reply as an array of reply arrays
        msgpack_pack_array(pk, cmds.size);

        for(size_t icmd = 0 ; icmd < cmds.size ; icmd++)
        {
            msgpack_object cmd = cmds.ptr[icmd];
            assert(cmd.type == MSGPACK_OBJECT_ARRAY);

            msgpack_object_array cmd_arr = cmd.via.array;
            if(taintmon_dispatcher(cmd_arr, pk))
            {
                fprintf(stderr, "Error running command:\n");
                msgpack_object_print(stderr, obj);
                fprintf(stderr, "\n");
            }
        }
    }
    else if (is_list_of_cmds == 0)
    {
        // no preparation needed for the reply, the reply will
        // directly contain the (only) reply array

        msgpack_object_array cmd_arr = obj.via.array;
        if(taintmon_dispatcher(cmd_arr, pk))
        {
            fprintf(stderr, "Error running command:\n");
            msgpack_object_print(stderr, obj);
            fprintf(stderr, "\n");
        }
    }
    else
    {
        fprintf(stderr, "ERROR: unexpected request wrapping type for ");
        msgpack_object_print(stderr, obj);
        fprintf(stderr, "\n");
        return 1;
    }

    // The object is ready to send in the packer
    return 0;
}

int taint_cmd_process_cmd_block(msgpack_unpacker * unp, msgpack_packer * pk)
{
    /*
     * Parse the user command. The block of text has potentially
     * not been fully received yet. The available data will be
     * passed to msgpack's stream unpacker, and all the next formed
     * commands will be parsed.
     *
     * On return: returns -1 on error, 0 if no command is available in
     * the block, and 1 if a command has been parsed and executed. In the
     * last case, the function should be re-executed as more commands
     * may be available.
     */


    // unpacked can be reused from one parse to the next:
    // msgpack_unpacker_next does the destruction
    // so make it a static var
    static msgpack_unpacked und = {0};

    msgpack_unpack_return ret = msgpack_unpacker_next(unp, &und);
    switch(ret) {
        case MSGPACK_UNPACK_SUCCESS:
        {
            /* Extract msgpack_object and use it. */
            if(taintmon_req_handler(und.data, pk))
                return -1;
            return 1;
        }
        case MSGPACK_UNPACK_CONTINUE:
            /* cheking capacity, reserve buffer, copy additional data to the buffer, */
            /* notify consumed buffer size, then call msgpack_unpacker_next(&unp, &und) again */
            return 0;
        case MSGPACK_UNPACK_PARSE_ERROR:
            /* Error process */
            fprintf(stderr, "MsgPack parse error!\n");
            return -1;
        case MSGPACK_UNPACK_EXTRA_BYTES:
        case MSGPACK_UNPACK_NOMEM_ERROR:
            // these two should never be returned by the *_next API
            fprintf(stderr, "Error when unpacking request: unexpected msgpack error code.\n");
            exit(1);
    }

    // not reached
    return -1;
}