#include "taint_requests.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "params.h"

static int pack_ok(msgpack_packer * pk)
{
    // Append reply to the buffer
    msgpack_pack_map(pk, 1); // 1 pair

    // key
    char const cmd[] = "cmd";
    msgpack_pack_str(pk, sizeof(cmd) - 1);
    msgpack_pack_str_body(pk, cmd, sizeof(cmd) - 1); 
    // value
    char const ok[] = "ok";
    msgpack_pack_str(pk, sizeof(ok) - 1);
    msgpack_pack_str_body(pk, ok, sizeof(ok) - 1);

    return 0;
}


static int doTaintRamRange(msgpack_packer * pk, uint64_t start, uint64_t end, uint8_t t)
{
    fprintf(stderr, "doTaintPhysRange(%lx, %lx, %d)\n", start, end, t);

    memset(shadow_mem + start, t, end - start);

    pack_ok(pk);

    return 0;
}

static int doGetTaintRamRange(msgpack_packer * pk, uint64_t start, uint64_t end)
{
    fprintf(stderr, "doGetTaintPhysRange(%lx, %lx)\n", start, end);

    // Append reply to the buffer
    msgpack_pack_map(pk, 2); // 2 pairs

    // key
    char const cmd[] = "cmd";
    msgpack_pack_str(pk, sizeof(cmd) - 1);
    msgpack_pack_str_body(pk, cmd, sizeof(cmd) - 1); 
    // value
    char const ok[] = "ok";
    msgpack_pack_str(pk, sizeof(ok) - 1);
    msgpack_pack_str_body(pk, ok, sizeof(ok) - 1);


    // key
    char const taint[] = "taint";
    msgpack_pack_str(pk, sizeof(taint) - 1);
    msgpack_pack_str_body(pk, taint, sizeof(taint) - 1); 
    // Value
    msgpack_pack_bin(pk, end - start);
    msgpack_pack_bin_body(pk, shadow_mem + start, end - start);

    return 0;
}

static int doTaintReg(msgpack_packer * pk, uint8_t regid, uint64_t treg)
{
    fprintf(stderr, "doTaintReg(%" PRIu8 ", %" PRIx64 ")\n", regid, treg);

    // FIXME: locking! Or really? Could also say:
    // accessing during execution is UB
    shadow_regs[regid] = treg;

    pack_ok(pk);

    return 0;
}

static int doGetTaintReg(msgpack_packer * pk, uint8_t regid)
{
    fprintf(stderr, "doGetTaintReg(%" PRIu8 ")\n", regid);

    // FIXME: locking! Or really? Could also say:
    // accessing during execution is UB
    uint64_t t = shadow_regs[regid];


    // Append reply to the buffer
    msgpack_pack_map(pk, 2); // 2 pairs

    // key
    char const cmd[] = "cmd";
    msgpack_pack_str(pk, sizeof(cmd) - 1);
    msgpack_pack_str_body(pk, cmd, sizeof(cmd) - 1); 
    // value
    char const ok[] = "ok";
    msgpack_pack_str(pk, sizeof(ok) - 1);
    msgpack_pack_str_body(pk, ok, sizeof(ok) - 1);


    // key
    char const taint[] = "t64";
    msgpack_pack_str(pk, sizeof(taint) - 1);
    msgpack_pack_str_body(pk, taint, sizeof(taint) - 1); 
    // Value
    msgpack_pack_bin(pk, 8);
    msgpack_pack_bin_body(pk, &t, 8);

    return 0;
}

#define CMD_CMP(cmd, str) \
    ((sizeof(str) - 1 == cmd.size) && ((memcmp(cmd.ptr, str, sizeof(str) - 1) == 0)))



static int taintmon_dispatcher(msgpack_object_map map, msgpack_packer * pk)
{
    // Parse the map into command and arguments
    // Write the reply to packer pk

    msgpack_object_str cmd = {0};
    uint64_t start = 0;
    uint64_t end = 0;
    uint8_t reg = 0;
    uint8_t t8 = -1;
    uint64_t t64 = 0;

    for (size_t i = 0 ; i < map.size ; i++)
    {
        msgpack_object_kv pair = map.ptr[i];

        if (pair.key.type != MSGPACK_OBJECT_STR)
        {
            fprintf(stderr, "Skipping invalid key at position %zu\n", i);
            continue;
        }
        
        if(CMD_CMP(pair.key.via.str, "cmd"))
        {
            assert(pair.val.type == MSGPACK_OBJECT_STR);
            cmd = pair.val.via.str;
        }
        else if(CMD_CMP(pair.key.via.str, "start"))
        {
            assert(pair.val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            start = pair.val.via.u64;
        }
        else if(CMD_CMP(pair.key.via.str, "end"))
        {
            assert(pair.val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            end = pair.val.via.u64;
        }
        else if(CMD_CMP(pair.key.via.str, "reg"))
        {
            assert(pair.val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            reg = pair.val.via.u64;
        }
        else if(CMD_CMP(pair.key.via.str, "t8"))
        {
            assert(pair.val.type == MSGPACK_OBJECT_BIN);
            assert(pair.val.via.bin.size == 1);
            memcpy(&t8, pair.val.via.bin.ptr, 1);
        }
        else if(CMD_CMP(pair.key.via.str, "t64"))
        {
            assert(pair.val.type == MSGPACK_OBJECT_BIN);
            assert(pair.val.via.bin.size == 8);
            memcpy(&t64, pair.val.via.bin.ptr, 8);

        }
        else
        {
            fprintf(stderr, "Skipping unknown key at position %zu: %.*s\n", i, pair.key.via.str.size, pair.key.via.str.ptr);
        }
    }
    
    // Now dispatch
    int ret;
    if (CMD_CMP(cmd, "set-taint-ram-range"))
    {
        ret = doTaintRamRange(pk, start, end, t8);
    }
    else if (CMD_CMP(cmd, "get-taint-ram-range"))
    {
        ret = doGetTaintRamRange(pk, start, end);
    }
    else if (CMD_CMP(cmd, "set-taint-reg"))
    {
        ret = doTaintReg(pk, reg, t64);
    }
    else if (CMD_CMP(cmd, "get-taint-reg"))
    {
        ret = doGetTaintReg(pk, reg);
    }
    else
    {
        fprintf(stderr, "Warning: skipping request, invalid or inexistant \"cmd\" in command map.\n");
        ret = 1;
    }

    return ret;
}


static int taintmon_req_handler(msgpack_object obj, msgpack_packer * pk)
{
    fprintf(stderr, "Handling command:\n");
    msgpack_object_print(stderr, obj);
    fprintf(stderr, "\n");

    /*
     * The serialized object can either be a command (=a key value list), or a list
     * of commands (list of key value lists)
     * 
     * Will pack the reply in the packer (by appending, will not empty the
     * packer if it already contains msgpack objects!)
     */

    if(obj.type == MSGPACK_OBJECT_ARRAY)
    {
        msgpack_object_array cmds = obj.via.array;

        // prepare the reply as an array of reply maps
        msgpack_pack_array(pk, cmds.size);

        for(size_t icmd = 0 ; icmd < cmds.size ; icmd++)
        {
            msgpack_object cmd = cmds.ptr[icmd];
            assert(cmd.type == MSGPACK_OBJECT_MAP);

            msgpack_object_map cmd_map = cmd.via.map;
            if(taintmon_dispatcher(cmd_map, pk))
            {
                fprintf(stderr, "Error running command:\n");
                msgpack_object_print(stderr, obj);
                fprintf(stderr, "\n");
            }
        }
    }
    else if (obj.type == MSGPACK_OBJECT_MAP)
    {
        // no preparation needed for the reply, the reply will
        // directly contain the (only) reply map

        msgpack_object_map cmd_map = obj.via.map;
        if(taintmon_dispatcher(cmd_map, pk))
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