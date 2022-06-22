/*
 * Copyright (C) 2022, Valentin Ogier <contact@vogier.fr>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <unistd.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <qemu-plugin.h>

#define HMP_SOCK_PATH "/tmp/qemu_hmp.sock"

/*
 * Taint tracking plugin.
 *
 * Currently only implemented for RISCV system emulation.
 */

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

int hmp_sock_fd = -1;

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

    printf("Memory access at vaddr %" PRIx64 ", physaddr %" PRIx64 "\n", vaddr, phys_addr);


    // Get register values from monitor

    struct sockaddr_un hmp_addr = {
        .sun_family = AF_UNIX,
        .sun_path = HMP_SOCK_PATH,
    };


    if(connect(hmp_sock_fd, (struct sockaddr*)(&hmp_addr), sizeof(hmp_addr)) < 0)
    {
        perror("Unable to connect HMP socket");
        exit(1);
    }


    static char const hmp_dump_regs_cmd[] = "info registers\n";


    // 2. write command
    // QEMU will only start processing the command once we have read the prompt.

    //TODO: handle partial sends
    ssize_t n_sent = send(hmp_sock_fd, hmp_dump_regs_cmd, sizeof(hmp_dump_regs_cmd), 0);
    if (n_sent < sizeof(hmp_dump_regs_cmd))
    {
        fprintf(stderr, "Partial sends of command not handled.");
        exit(1);
    }

    size_t const max_line_len = 2048;
    
    size_t cur_line_len = 0;
    char * cur_line = malloc((max_line_len + 1) * sizeof(char));
    memset(cur_line, 0, max_line_len + 1);


    size_t next_line_len = 0;
    char * next_line = malloc((max_line_len + 1) * sizeof(char));
    memset(next_line, 0, max_line_len + 1);

    size_t cur_line_idx = 0;

    while(true)
    {

        while((cur_line_idx < cur_line_len) && cur_line[cur_line_idx] != '\n')
        {
            cur_line_idx++;
        }
        if (cur_line_idx >= cur_line_len)
        {
            // reached end of buffer: need more data!
            ssize_t n_recv = recv(hmp_sock_fd, cur_line + cur_line_len, max_line_len - cur_line_len, 0);

            if(n_recv < 0)
            {
                perror("Error reading from HMP");
                exit(1);
            }

            cur_line_len += n_recv;
        }
        else
        {
            // found '\n', move additionnal data to next_line and process current line
            next_line_len = cur_line_len - cur_line_idx;
            char * remaining_char_ptr = cur_line + cur_line_idx + 1;
            memcpy(next_line, remaining_char_ptr, next_line_len * sizeof(char));

            // zero-terminate cur_line
            *remaining_char_ptr = '\0';
            cur_line_len = cur_line_idx;


            // we have a line to process in cur_line
            printf("(%zu) %s", cur_line_len, cur_line);
            //PROCESS....


            // next_line becomes current_line
            char * t = cur_line;
            cur_line = next_line;
            cur_line_len = next_line_len;
            cur_line_idx = 0;

            // swap buffers
            next_line = t;
            next_line_len = 0;
        }

    }


    // free ressources
    
    if(close(hmp_sock_fd) < 0){
        perror("Error closing HMP socket connection");
        exit(1);
    }
    
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

        void *data = NULL;
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, data);

        // qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
        //                                 QEMU_PLUGIN_CB_NO_REGS, data);
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    //qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    
    if ((hmp_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        perror("Unable to create HMP socket");
        exit(1);
    }
 



    return 0;
}
