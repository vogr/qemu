#include "monitor.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>

#include <msgpack.h>

#include "params.h"

// see msgpack wiki: https://github.com/msgpack/msgpack-c/wiki/v2_0_c_overview

static msgpack_unpacker unp = {0};

static msgpack_sbuffer packing_sbuf = {0};
static msgpack_packer pk = {0};



static int peersock = -1;
static uint64_t cmd_counter = 0;

// helper function to make sure the sbuf is large enough before
// requesting a copy (and in particular outside the critical section)
static int sbuf_reserve_len(msgpack_sbuffer * sbuf, size_t len)
{
        if(sbuf->alloc - sbuf->size < len) {
        void* tmp;
        size_t nsize = (sbuf->alloc) ?
                sbuf->alloc * 2 : MSGPACK_SBUFFER_INIT_SIZE;

        while(nsize < sbuf->size + len) {
            size_t tmp_nsize = nsize * 2;
            if (tmp_nsize <= nsize) {
                nsize = sbuf->size + len;
                break;
            }
            nsize = tmp_nsize;
        }

        tmp = realloc(sbuf->data, nsize);
        if(!tmp) { return -1; }

        sbuf->data = (char*)tmp;
        sbuf->alloc = nsize;
    }
    return 0;
}


static int sendall(int fd, size_t size, char * buf)
{
    size_t nsent = 0;
    while(nsent < size)
    {
        ssize_t n = send(fd, buf + nsent, size - nsent, 0);
        if (n < 0)
        {
            perror("Error sending ok reply");
            return 1;
        }
        nsent += n;
    }

    return 0;
}

static int send_ok(void)
{
    // Empty buffer
    msgpack_sbuffer_clear(&packing_sbuf);
    
    // Fill buffer
    msgpack_pack_map(&pk, 1); // 1 pair

    // key
    char const cmd[] = "cmd";
    msgpack_pack_str(&pk, sizeof(cmd) - 1);
    msgpack_pack_str_body(&pk, cmd, sizeof(cmd) - 1); 
    // value
    char const ok[] = "ok";
    msgpack_pack_str(&pk, sizeof(ok) - 1);
    msgpack_pack_str_body(&pk, ok, sizeof(ok) - 1);

    return sendall(peersock, packing_sbuf.size, packing_sbuf.data);
}


static int msgpack_init(void)
{
    if(! msgpack_unpacker_init(&unp, MSGPACK_UNPACKER_INIT_BUFFER_SIZE))
    {
        fprintf(stderr, "MsgPack: Error on unpacker init.");
        exit(1);
    }

    msgpack_packer_init(&pk, &packing_sbuf, msgpack_sbuffer_write);

    return 0;
}

static int doTaintRamRange(uint64_t start, uint64_t end, uint8_t t)
{
    fprintf(stderr, "doTaintPhysRange(%lx, %lx, %d)\n", start, end, t);
    cmd_counter++;

    memset(shadow_mem + start, t, end - start);

    send_ok();

    return 0;
}

static int doGetTaintRamRange(uint64_t start, uint64_t end)
{
    fprintf(stderr, "doGetTaintPhysRange(%lx, %lx)\n", start, end);
    cmd_counter++;

    // Empty buffer
    msgpack_sbuffer_clear(&packing_sbuf);

    // Fill buffer
    msgpack_pack_map(&pk, 2); // 2 pairs

    // key
    char const cmd[] = "cmd";
    msgpack_pack_str(&pk, sizeof(cmd) - 1);
    msgpack_pack_str_body(&pk, cmd, sizeof(cmd) - 1); 
    // value
    char const ok[] = "ok";
    msgpack_pack_str(&pk, sizeof(ok) - 1);
    msgpack_pack_str_body(&pk, ok, sizeof(ok) - 1);


    // key
    char const taint[] = "taint";
    msgpack_pack_str(&pk, sizeof(taint) - 1);
    msgpack_pack_str_body(&pk, taint, sizeof(taint) - 1); 
    // Value
    msgpack_pack_bin(&pk, end - start);
    msgpack_pack_bin_body(&pk, shadow_mem + start, end - start);

    return sendall(peersock, packing_sbuf.size, packing_sbuf.data);
}

static int doTaintReg(uint8_t regid, uint64_t treg)
{
    fprintf(stderr, "doTaintReg(%" PRIu8 ", %" PRIx64 ")\n", regid, treg);
    cmd_counter++;


    // FIXME: locking! Or really? Could also say:
    // accessing during execution is UB
    shadow_regs[regid] = treg;

    return send_ok();
}

static int doGetTaintReg(uint8_t regid)
{
    fprintf(stderr, "doGetTaintReg(%" PRIu8 ")\n", regid);
    cmd_counter++;


    // FIXME: locking! Or really? Could also say:
    // accessing during execution is UB
    uint64_t t = shadow_regs[regid];


    // Empty buffer
    msgpack_sbuffer_clear(&packing_sbuf);

    // Fill buffer
    msgpack_pack_map(&pk, 2); // 2 pairs

    // key
    char const cmd[] = "cmd";
    msgpack_pack_str(&pk, sizeof(cmd) - 1);
    msgpack_pack_str_body(&pk, cmd, sizeof(cmd) - 1); 
    // value
    char const ok[] = "ok";
    msgpack_pack_str(&pk, sizeof(ok) - 1);
    msgpack_pack_str_body(&pk, ok, sizeof(ok) - 1);


    // key
    char const taint[] = "t64";
    msgpack_pack_str(&pk, sizeof(taint) - 1);
    msgpack_pack_str_body(&pk, taint, sizeof(taint) - 1); 
    // Value
    msgpack_pack_bin(&pk, 8);
    msgpack_pack_bin_body(&pk, &t, 8);

    return sendall(peersock, packing_sbuf.size, packing_sbuf.data);

}

#define CMD_CMP(cmd, str) \
    ((sizeof(str) - 1 == cmd.size) && ((memcmp(cmd.ptr, str, sizeof(str) - 1) == 0)))

static int taintmon_dispatcher(msgpack_object obj)
{
    fprintf(stderr, "Recv object:\n");
    msgpack_object_print(stderr, obj);
    fprintf(stderr, "\n");


    assert(obj.type == MSGPACK_OBJECT_MAP);
    msgpack_object_map map = obj.via.map;

    // Parse the map into command and arguments

    msgpack_object_str cmd = {0};
    uint64_t start = 0;
    uint64_t end = 0;
    uint8_t vcpu = 0;
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
        else if(CMD_CMP(pair.key.via.str, "vcpu"))
        {
            assert(pair.val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            vcpu = pair.val.via.u64;
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
        ret = doTaintRamRange(start, end, t8);
    }
    else if (CMD_CMP(cmd, "get-taint-ram-range"))
    {
        ret = doGetTaintRamRange(start, end);
    }
    else if (CMD_CMP(cmd, "set-taint-reg"))
    {
        ret = doTaintReg(reg, t64);
    }
    else if (CMD_CMP(cmd, "get-taint-reg"))
    {
        ret = doGetTaintReg(reg);
    }
    else
    {
        fprintf(stderr, "Warning: skipping request, invalid or inexistant \"cmd\" in \n");
        msgpack_object_print(stderr, obj);
        fprintf(stderr, "\n");

        ret = 1;
    }

    return ret;
}

static int process_recvd_block(void)
{
    /*
     * Parse the user command. The block of text has potentially
     * not been fully received yet. The available data will be
     * passed to msgpack's stream unpacker, and all the fully formed
     * commands will be parsed.
     */
    
    
    // unpacked can be reused from one parse to the next: 
    // msgpack_unpacker_next does the destruction
    static msgpack_unpacked und = {0};

    while(1)
    {
        msgpack_unpack_return ret = msgpack_unpacker_next(&unp, &und);
        switch(ret) {
            case MSGPACK_UNPACK_SUCCESS:
            {
                /* Extract msgpack_object and use it. */
                taintmon_dispatcher(und.data);
                break;
            }
            case MSGPACK_UNPACK_CONTINUE:
                /* cheking capacity, reserve buffer, copy additional data to the buffer, */
                /* notify consumed buffer size, then call msgpack_unpacker_next(&unp, &und) again */
                return 0;
            case MSGPACK_UNPACK_PARSE_ERROR:
                /* Error process */
                fprintf(stderr, "MsgPack parse error!\n");
                return 1;
            case MSGPACK_UNPACK_EXTRA_BYTES:
            case MSGPACK_UNPACK_NOMEM_ERROR:
                // these two should never be returned by the *_next API
                fprintf(stderr, "Error when unpacking request: unexpected msgpack error code.\n");
                exit(1);
        }
    }

}


void taint_monitor_loop(char const * taintsock_path)
{
    /* Open the socket */

    fprintf(stderr, "Opening socket %s\n", taintsock_path);

    int taintsock = socket(AF_UNIX, SOCK_STREAM, 0);
    if(taintsock < 0)
    {
        perror("Error opening taint monitor socket");
        exit(1);
    }

    struct sockaddr_un taintsock_addr = {
        .sun_family = AF_UNIX
    };
    strncpy(taintsock_addr.sun_path, taintsock_path, sizeof(taintsock_addr.sun_path));

    unlink(taintsock_addr.sun_path);

    if(bind(taintsock, (struct sockaddr const *)&taintsock_addr, sizeof(struct sockaddr_un)) < 0)
    {
        perror("Error binding taint monitor socket");
        exit(1);
    }

    if (listen(taintsock, 50) < 0)
    {
        perror("Error listening on taint monitor");
        exit(1);
    }
    

    /*
     * Connect loop.
     * Allows one peer at a time.
     */




    while(1)
    {
        /* Reset msgpack's unpacker */
        msgpack_init();


        struct sockaddr_un peer_addr = {0};
        socklen_t peer_addr_size = 0;
        peersock = accept(taintsock, (struct sockaddr *) &peer_addr,
                            &peer_addr_size);

        if(peersock < 0)
        {
            perror("Error accepting peer from taint monitor:");
            exit(1);
        }

        /*
         * Recv loop
         * Directly recv new data into msgpack's unpack buffer.
         * Parse the partial messages on every recv, and process
         * messages as they become fully available.
         */
        while(1)
        {
            size_t cur_capacity = msgpack_unpacker_buffer_capacity(&unp);
            if (cur_capacity < 1024)
            {
                fprintf(stderr, "MsgPack: extend recv buffer size.\n");
                // Buffer capacity is low ! Extend it before next recv.
                if(! msgpack_unpacker_reserve_buffer(&unp, 2 * cur_capacity))
                {
                    fprintf(stderr, "MsgPack: error when extending recv buffer size.\n");
                    exit(1);
                }
            }

            // Recv new data
            fprintf(stderr, "Waiting for new data...\n");
            ssize_t nread = recv(peersock, msgpack_unpacker_buffer(&unp), msgpack_unpacker_buffer_capacity(&unp), 0);
            if (nread < 0)
            {
                perror("Error on taint monitor read");
                exit(1);
            }
            else if(nread == 0)
            {
                // end of stream
                break;
            }

            // as soon as we receive data, stop the taint propagation
            pthread_mutex_lock(&shadow_lock);


            fprintf(stderr, "Received %zu bytes\n", (size_t)nread);
            for(ssize_t i = 0; i < nread; i++)
            {
                fprintf(stderr, "%x", *(msgpack_unpacker_buffer(&unp) + i));
            }
            fprintf(stderr, "\n");

            // Update MsgPack internal counters
            msgpack_unpacker_buffer_consumed(&unp, nread);



            process_recvd_block();

            // resume taint propagation
            pthread_mutex_unlock(&shadow_lock);

        }

        msgpack_unpacker_destroy(&unp);
    }
}



void * taint_monitor_loop_pthread(void * args)
{
    taint_monitor_loop((char const *)args);
    return NULL;
}