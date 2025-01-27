#include "monitor.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <msgpack.h>

#include "taint_requests.h"
#include "params.h"
#include "monitor_lock.h"
#include "logging.h"

// see msgpack wiki: https://github.com/msgpack/msgpack-c/wiki/v2_0_c_overview

static msgpack_unpacker unp = {0};

static msgpack_sbuffer packing_sbuf = {0};
static msgpack_packer pk = {0};


static int taintsock = -1;

static int monitor_peersock = -1;

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


int monitor_sendall(size_t size, char * buf)
{
    size_t nsent = 0;
    while(nsent < size)
    {
        ssize_t n = send(monitor_peersock, buf + nsent, size - nsent, 0);
        if (n < 0)
        {
            return 1;
        }
        nsent += n;
    }

    return 0;
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


void taint_monitor_loop(char const * taintsock_path)
{

    /* Prepare serializer */
    msgpack_init();

    /* Open the socket */
    _DEBUG("MON: Opening socket %s\n", taintsock_path);

    taintsock = socket(AF_UNIX, SOCK_STREAM, 0);
    if(taintsock < 0)
    {
        perror("Error opening taint monitor socket");
        exit(1);
    }

    struct sockaddr_un taintsock_addr = {
        .sun_family = AF_UNIX
    };

    size_t path_len = strnlen(taintsock_path, sizeof(taintsock_addr.sun_path) - 1);
    memcpy(taintsock_addr.sun_path, taintsock_path, path_len);

    unlink(taintsock_addr.sun_path);

    if(bind(taintsock, (struct sockaddr const *)&taintsock_addr, sizeof(struct sockaddr_un)) < 0)
    {
        perror("Error binding taint monitor socket");
        exit(1);
    }

    if (listen(taintsock, 1) < 0)
    {
        perror("Error listening on taint monitor");
        exit(1);
    }
    

    /* Connect one peer */
    _DEBUG("MON: Waiting for a peer to connect...\n");
    struct sockaddr_un peer_addr = {0};
    socklen_t peer_addr_size = 0;
    monitor_peersock = accept(taintsock, (struct sockaddr *) &peer_addr,
                        &peer_addr_size);

    if(monitor_peersock < 0)
    {
        fprintf(stderr, "Error accepting peer on monitor socket\n");
        exit(1);
    }
    _DEBUG("MON: Peer connected.\n");

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
            if(! msgpack_unpacker_reserve_buffer(&unp, 1024))
            {
                fprintf(stderr, "MsgPack: error when extending recv buffer size.\n");
                exit(1);
            }
        }

        // Recv new data
        _DEBUG("MON: Waiting for new request...\n");
        ssize_t nread = recv(monitor_peersock, msgpack_unpacker_buffer(&unp), msgpack_unpacker_buffer_capacity(&unp), 0);
        if (nread < 0)
        {
            perror("Error on taint monitor read");
            exit(1);
        }
        else if(nread == 0)
        {
            // end of stream
            fprintf(stderr, "Unexpected end of stream on monitor.\n");
            exit(1);
        }


        _DEBUG("MON: Received %zu bytes\n", (size_t)nread);
        for(ssize_t i = 0; i < nread; i++)
        {
            _DEBUG("%x", *(msgpack_unpacker_buffer(&unp) + i));
        }
        _DEBUG("\n");

        // Update MsgPack internal counters
        msgpack_unpacker_buffer_consumed(&unp, nread);

        // Empty the packer's buffer
        // /!\ assumes that the packers buffer is an sbuffer!
        msgpack_sbuffer_clear(&packing_sbuf);

        // Acquire lock before processing the commands
        // we will only unlock it to let the main process
        // known a resumption can happen
        pthread_mutex_lock(&monitor_sendrecv_mutex);

        int cmd_read = 0;
        do
        {
            cmd_read = taint_cmd_process_cmd_block(&unp, &pk);
        } while (cmd_read > 0);
        
        // all the availabe objects have been processed, 
        // the command excecuted and the replied written
        // to the packer. Send all the replies
        if (packing_sbuf.size > 0)
        {
            if(monitor_sendall(packing_sbuf.size, packing_sbuf.data))
            {
                perror("Error sending msgpack object reply over socket");
            }
        }

        pthread_mutex_unlock(&monitor_sendrecv_mutex);

    }

    msgpack_unpacker_destroy(&unp);
}



void * taint_monitor_loop_pthread(void * args)
{
    taint_monitor_loop((char const *)args);
    return NULL;
}