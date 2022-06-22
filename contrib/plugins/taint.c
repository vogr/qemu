/*
 * Copyright (C) 2022, Valentin Ogier <contact@vogier.fr>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <inttypes.h>
#include <stdio.h>
#include <glib.h>

#include <unistd.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>

#include <qemu-plugin.h>

#define HMP_SOCK_PATH "/tmp/qemu_hmp.sock"

/*
 * Taint tracking plugin.
 *
 * Currently only implemented for RISCV system emulation.
 */

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

int hmp_socket_fd = -1;

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


    if(connect(hmp_socket_fd, (struct sockaddr*)(&hmp_addr), sizeof(hmp_addr)) < 0)
    {
        perror("Unable to connect HMP socket");
        exit(1);
    }


    static char const hmp_dump_regs_cmd[] = "info registers\n";


    // read prompt and reply
    FILE * hmp_read_fp = NULL;
    int hmp_read_fd = dup(hmp_socket_fd);
    if((hmp_read_fp = fdopen(hmp_read_fd, "r")) == NULL)
    {
        perror("Unable to open HMP socket for reading.");
    }

    // write command
    FILE * hmp_write_fp = NULL;
    int hmp_write_fd = dup(hmp_socket_fd);
    if((hmp_write_fp = fdopen(hmp_write_fd, "w")) == NULL)
    {
        perror("Unable to open HMP socket for writing.");
    }


    char * line = NULL;
    size_t linebuf_len = 0;
    ssize_t line_len = 0;

    // 2. write command
    size_t write_ret = fwrite(hmp_dump_regs_cmd, sizeof(hmp_dump_regs_cmd), 1, hmp_write_fp);
    if (write_ret != 1)
    {
        fprintf(stderr, "Error writing to HMP socket.\n");
        exit(1);
    }
    

    // 1. read prompt
    for(int i = 0 ; i < 2 ; i++)
    {
        errno = 0;
        line_len = getline(&line, &linebuf_len, hmp_read_fp);
        if(line_len < 0)
        {
            if(errno)
            {
                perror("Failed to read stream due to an error");
                exit(1);
            }
            else if(feof(hmp_read_fp))
            {
                fprintf(stderr, "Failed to read stream due to an unexpected EOF");
                exit(1);
            }
            else
            {
                fprintf(stderr, "Failed to read stream due to UNKNOWN");
                exit(1);
            }
        }
        printf("Read %zd bytes:\n%s",  line_len, line);
    }


    // 3. read reply
    errno = 0;
    line_len = getline(&line, &linebuf_len, hmp_read_fp);
    if(line_len < 0)
    {
        if(errno)
        {
            perror("Failed to read stream due to an error");
            exit(1);
        }
        else if(feof(hmp_read_fp))
        {
            fprintf(stderr, "Failed to read stream due to an unexpected EOF");
            exit(1);
        }
        else
        {
            fprintf(stderr, "Failed to read stream due to UNKNOWN");
            exit(1);
        }
    }
    printf("Read %zd bytes:\n%s",  line_len, line);

    // free ressources

    free(line);
    
    if(fclose(hmp_write_fp) < 0)
    {
        perror("Error closing writing HMP stream.");
        exit(1);
    }

    if(fclose(hmp_read_fp) < 0)
    {
        perror("Error closing reading HMP stream.");
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
    
    if ((hmp_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        perror("Unable to create HMP socket");
        exit(1);
    }
 



    return 0;
}
