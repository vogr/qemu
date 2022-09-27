#include "hypernotify.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>


#include <msgpack.h>

#include "logging.h"
#include "monitor.h"
#include "monitor_lock.h"

/*
 * The monitor runs in a separate thread. Instead of protecting the
 * monitor's packer with a mutex, and sharing it with the main thread
 * (here), we use a private packer. This has the advantage that we
 * don't have to wait for the other requests to be processed to prepare
 * and send the notification.
 * 
 * We will use a different socket so as to avoid using synchronisation
 * primitives. The ordering comes naturally from the order of requests
 *
 * TODO: also make it possible to call "resume" from the monitor socket
 * 
 *  -notify->
 *  <-taint_req-
 *      **wait**
 *  -taint_rep->
 *  <--resume-- 
 *    **wait**
 *   resumption
 * to
 *  -notify->
 *  <-taint_req+resume-
 *      **wait**
 *  -taint_rep->
 *  resumption
 */


static msgpack_sbuffer packing_sbuf = {0};
static msgpack_packer pk = {0};



void monitor_wait_for_resume_command(void)
{
    // to prevent race condition: don't allow "resume" command
    // to go through before we're ready to process it
    pthread_mutex_lock(&monitor_sendrecv_mutex);

    _DEBUG("HN: Waiting for resume command...\n");

    // wait for "resume" command.
    // Return the lock to the monitor, so that it processes commands,
    // and wait for the condition to be true.
    while(!monitor_resume_recvd)
    {
        pthread_cond_wait(&monitor_resume_recvd_cv, &monitor_sendrecv_mutex);
    }

    _DEBUG("HN: Resuming!\n");


    // restore condition to false
    monitor_resume_recvd = false;

    // resume emulation, release the lock
    pthread_mutex_unlock(&monitor_sendrecv_mutex);
}


void init_hypernotify_handler(void)
{
    /*
     * Prepare the serializer
     */

    msgpack_packer_init(&pk, &packing_sbuf, msgpack_sbuffer_write);
}



void vcpu_insn_hypernotify_cb(unsigned int vcpu_index, void *userdata)
{
    /*
     * send a notification and wait for a "resume" command
     * before resuming the emulation.
     * 
     * Notification
     * ["notify", vcpu_index, notify_idx]
     */

    struct HypernotifyData * hyp_data = userdata;
    int id = hyp_data->id;

    // prepare notification to send
    msgpack_sbuffer_clear(&packing_sbuf);

    // 3 elements: the command, the vcpu and the hypercall index.
    msgpack_pack_array(&pk, 3);

    // string
    char cmd[] = "notify";
    msgpack_pack_str(&pk, sizeof(cmd) - 1);
    msgpack_pack_str_body(&pk, cmd, sizeof(cmd) - 1);

    msgpack_pack_unsigned_int(&pk, vcpu_index);

    msgpack_pack_int(&pk, id);

    // we can send on the monitor socket without locking:
    // no interleaving should happen, as the hypernotify
    // instruction can only be encountered during emulation
    // and a client mustn't use taint control during the emulation
    fprintf(stderr, "Send notify(vcpu=%u, id=%d) \n", vcpu_index, id);
    _DEBUG("HN: Send notifyvcpu=%u, id=%d) \n", vcpu_index, id);
    if(monitor_sendall(packing_sbuf.size, packing_sbuf.data))
    {
        perror("Error sending notification over monitor socket");
    }


    monitor_wait_for_resume_command();
}