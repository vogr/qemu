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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <qemu-plugin.h>

#define HMP_HOSTNAME "localhost"
#define HMP_PORT "55555"

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


    enum { BEFORE_PARSE, IS_PARSING, PARSING_DONE } parse_state = BEFORE_PARSE;
    while(parse_state != PARSING_DONE)
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
            next_line_len = cur_line_len - cur_line_idx - 1;
            char * remaining_char_ptr = cur_line + cur_line_idx + 1;
            memcpy(next_line, remaining_char_ptr, next_line_len * sizeof(char));

            // zero-terminate cur_line
            *remaining_char_ptr = '\0';
            cur_line_len = cur_line_idx;

            if (parse_state == BEFORE_PARSE)
            {
                static const char first_line_prefix[] = " x0/zero";
                if (strncmp(cur_line, first_line_prefix, sizeof(first_line_prefix) - 1) == 0)
                {
                    parse_state = IS_PARSING;
                    // falloff to next stage, don't `continue`
                }
            }

            if (parse_state == IS_PARSING)
            {
                // we have a line to process in cur_line
                printf("%s", cur_line);
                //PROCESS....

                static const char last_line_prefix[] = " f28/ft8";
                if (strncmp(cur_line, last_line_prefix, sizeof(last_line_prefix) - 1) == 0)
                {
                    parse_state = PARSING_DONE;
                }
            }


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
    free(next_line);
    free(cur_line);
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
    
 
    // IPv4/IPv6 TCP socket
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM
    };

    struct addrinfo * addr_candidates;
    int ret = getaddrinfo(HMP_HOSTNAME, HMP_PORT, &hints, &addr_candidates);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        exit(1);
    }

    fprintf(stderr, "Connecting to %s:%s\n", HMP_HOSTNAME, HMP_PORT);

    struct addrinfo * addr;
    for(addr = addr_candidates ; addr != NULL ; addr = addr->ai_next)
    {

        {
            char host[NI_MAXHOST] = {0};
            char service[NI_MAXSERV] = {0};
            int ret = getnameinfo(addr->ai_addr, addr->ai_addrlen,
                host, sizeof(host), service, sizeof(service), 0);
            if (ret < 0)
            {
                fprintf(stderr, "Couldn't resolve candidate hostname.\n");
            }
            else
            {
                fprintf(stderr, "Candidate: %s:%s\n", host, service);
            }
        }


        hmp_sock_fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if(hmp_sock_fd < 0)
        {
            perror("Failed to create socket for candidate address\n");
            fprintf(stderr, "Trying next candidate.\n");
            continue;
        }
        
        if (connect(hmp_sock_fd, addr->ai_addr, addr->ai_addrlen) < 0)
        {
            perror("Failed to connect socket for candidate address");
            fprintf(stderr, "Trying next candidate.\n");
            continue;
        }
        else
        {
            break;
        }
    }

    freeaddrinfo(addr_candidates);

    if (addr == NULL)
    {
        fprintf(stderr, "Couldn't create valid socket for any of the candidates.\n");
        exit(1);
    }




    return 0;
}



#if 0

// TODO: add plugin clos
// free ressources

if(close(hmp_sock_fd) < 0){
    perror("Error closing HMP socket connection");
    exit(1);
}

#endif