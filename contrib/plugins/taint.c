/*
 * Copyright (C) 2022, Valentin Ogier <contact@vogier.fr>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>

#include <qemu-plugin.h>

#define HMP_UNIX_SOCKET "/tmp/qemu_hmp.sock"

/*
 * Taint tracking plugin.
 *
 * Currently only implemented for RISCV system emulation.
 */

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static int hmp_sock_fd = -1;
 



//FIXME: move memory allocation out of callback, into init. 
// + cleanup in plugin close
enum parse_state_t { PARSING_BEFORE, PARSING_COPYING, PARSING_LAST_COPY, PARSING_DONE };
static void get_regs_repr(size_t all_regs_repr_max_len, char * all_regs_repr)
{
    // Get register values from monitor
    static char const hmp_dump_regs_cmd[] = "info registers\r\n";

    // 1. write command
    // QEMU will only start processing the command once we have read the prompt.

    //TODO: handle partial sends
    ssize_t n_sent = send(hmp_sock_fd, hmp_dump_regs_cmd, sizeof(hmp_dump_regs_cmd), 0);
    if (n_sent < sizeof(hmp_dump_regs_cmd))
    {
        fprintf(stderr, "Partial sends of command not handled.");
        exit(1);
    }


    // 2. read reply

    // Allocate two buffers for reading, we will swap between the two as we recv
    // called "line" but not line-based, delimiter is first_line_prefix
    size_t const max_line_len = 2047;
    
    size_t cur_line_len = 0;
    char * cur_line = malloc((max_line_len + 1) * sizeof(char));
    memset(cur_line, 0, max_line_len + 1);


    size_t next_line_len = 0;
    char * next_line = malloc((max_line_len + 1) * sizeof(char));
    memset(next_line, 0, max_line_len + 1);

    // Position of the parser head in the current line or in all_regs_repr
    size_t parser_head = 0;

    // Length of the register state string representation in the buffer
    size_t all_regs_string_len = 0;

    static const char first_line_prefix[] = " x0/zero";
    static const size_t flp_s = sizeof(first_line_prefix) / sizeof(char) - 1;
    static const char last_line_prefix[] = "f28/ft8";
    static const size_t llp_s = sizeof(last_line_prefix) / sizeof(char) - 1;

    //FIXME: use glib regex instead of strcmp to find flp, llp and end of line (\R)

    enum parse_state_t parse_state = PARSING_BEFORE;

    while(parse_state != PARSING_DONE)
    {
        while(parse_state == PARSING_BEFORE)
        {
            if ( (parser_head + (flp_s - 1) < cur_line_len ))
            {
                if (strncmp(first_line_prefix, cur_line + parser_head, flp_s) == 0)
                {
                    all_regs_string_len = cur_line_len - parser_head;
                    memcpy(all_regs_repr, cur_line + parser_head, all_regs_string_len);

                    parse_state = PARSING_COPYING;
                }
                else
                {
                    parser_head++;
                }
            }
            else
            {
                // reached end of buffer: need more data!
                // swap buffers, keep last characters for prefix matching
                size_t cpy_size = cur_line_len < (flp_s - 1) ? cur_line_len : (flp_s - 1);
                memcpy(next_line, cur_line + cur_line_len - cpy_size, cpy_size);
                
                char * t = next_line;
                next_line = cur_line;
                cur_line = t;

                cur_line_len = cpy_size;
                parser_head = 0;

                // need at least flp_s bytes
                while(cur_line_len < flp_s)
                {
                    ssize_t n_recv = recv(hmp_sock_fd, cur_line + cur_line_len, max_line_len - cur_line_len, 0);

                    if(n_recv < 0)
                    {
                        perror("Error reading from HMP");
                        exit(1);
                    }

                    cur_line_len += n_recv;
                }
            }
        }
        while (parse_state == PARSING_COPYING || parse_state == PARSING_LAST_COPY)
        {
            // copy all regs repr into a buffer
            // copy everything until the last_line_prefix is found, then copy until newline
            if ((parse_state == PARSING_COPYING) && (parser_head + (llp_s - 1) < (all_regs_string_len )))
            {
                if (strncmp(last_line_prefix, all_regs_repr + parser_head, llp_s) == 0)
                {
                    parse_state = PARSING_LAST_COPY;
                    parser_head += llp_s;
                }
                else
                {
                    parser_head++;
                }
            }
            else if ((parse_state == PARSING_LAST_COPY) && (parser_head < all_regs_string_len))
            {
                if (all_regs_repr[parser_head] == '\n')
                {
                    memset(all_regs_repr + parser_head + 1, 0, all_regs_string_len - parser_head - 1);
                    all_regs_string_len = parser_head;
                    parse_state = PARSING_DONE;
                }
                else
                {
                    parser_head++;
                }
            }
            else
            {
                if (all_regs_string_len >= all_regs_repr_max_len)
                {
                    fprintf(stderr, "ERROR: all_regs_repr buffer filled up before the last register to parse was reached\n");
                    exit(1);
                }

                // Need more data !
                ssize_t n_recv = recv(hmp_sock_fd, all_regs_repr + all_regs_string_len, all_regs_repr_max_len - all_regs_string_len, 0);

                if(n_recv < 0)
                {
                    perror("Error reading from HMP");
                    exit(1);
                }

                all_regs_string_len += n_recv;

            }
        }
    }
    free(next_line);
    free(cur_line);
}


// -1 for the NULL byte
static size_t const parse_reg_line_len = sizeof(" x0/zero  0000000000000000 x1/ra    00000000800001d6 x2/sp    0000000000000000 x3/gp    0000000000000000\r\n") / sizeof(char) - 1;
static size_t const parse_reg_line_offt = sizeof(" x0/zero  ") / sizeof(char) - 1;
static size_t const parse_reg_col_offt = sizeof("0000000000000000 x1/ra    ") / sizeof(char) - 1;
static uint32_t parse_one_reg(char const * regs_repr, int i_reg)
{
    /*
       Parse one register from the regs_repr
       Return a pointer pointing after the parsed block.


       Format:
```
 x0/zero  0000000000000000 x1/ra    00000000800001d6 x2/sp    0000000000000000 x3/gp    0000000000000000
 x4/tp    0000000000000000 x5/t0    0000000000000000 x6/t1    0000000000000000 x7/t2    0000000000000000
 x8/s0    0000000000000000 x9/s1    0000000000000000 x10/a0   0000000000000000 x11/a1   0000000087000000
 x12/a2   0000000000001028 x13/a3   0000000000000000 x14/a4   0000000000000000 x15/a5   0000000000000000
 x16/a6   0000000000000000 x17/a7   0000000000000000 x18/s2   0000000000000000 x19/s3   0000000000000000
 x20/s4   000000008001bd50 x21/s5   0000000080042ab0 x22/s6   0000000000000000 x23/s7   0000000000000000
 x24/s8   0000000000000000 x25/s9   0000000000000000 x26/s10  0000000000000000 x27/s11  0000000000000000
 x28/t3   0000000000000000 x29/t4   0000000000000000 x30/t5   0000000000000000 x31/t6   0000000000000000
 f0/ft0   0000000000000000 f1/ft1   0000000000000000 f2/ft2   0000000000000000 f3/ft3   0000000000000000
 f4/ft4   0000000000000000 f5/ft5   0000000000000000 f6/ft6   0000000000000000 f7/ft7   0000000000000000
 f8/fs0   0000000000000000 f9/fs1   0000000000000000 f10/fa0  0000000000000000 f11/fa1  0000000000000000
 f12/fa2  0000000000000000 f13/fa3  0000000000000000 f14/fa4  0000000000000000 f15/fa5  0000000000000000
 f16/fa6  0000000000000000 f17/fa7  0000000000000000 f18/fs2  0000000000000000 f19/fs3  0000000000000000
 f20/fs4  0000000000000000 f21/fs5  0000000000000000 f22/fs6  0000000000000000 f23/fs7  0000000000000000
 f24/fs8  0000000000000000 f25/fs9  0000000000000000 f26/fs10 0000000000000000 f27/fs11 0000000000000000
 f28/ft8  0000000000000000 f29/ft9  0000000000000000 f30/ft10 0000000000000000 f31/ft11 0000000000000000
```

    */



    int line = i_reg / 4;
    int col = i_reg % 4;

    size_t offt = line * parse_reg_line_len + parse_reg_line_offt + col * parse_reg_col_offt;
    char const * start_ptr = regs_repr + offt;
    char * endptr = NULL;

    errno = 0;
    uint32_t v = strtoul(start_ptr, &endptr, 16);

    if(errno != 0)
    {
        perror("strtoul");
        exit(1);
    }

    // make sure we only parsed the value
    assert(endptr - start_ptr == 16);

    return v;
}

static char const * parse_reg_repr(char const * regs_repr, uint32_t * regs)
{
    // Parse all registers from the regs_repr
    // Mostly for debugging as it is usually sufficient to parse 2 or 3 regs only
    
    // Returns a pointer to right after the parsed block
    for(int line = 0 ; line < 8 ; line++)
    {
        for(int col = 0; col < 4 ; col++)
        {
            int reg = line * 4 + col;

            size_t offt = line * parse_reg_line_len + parse_reg_line_offt + col * parse_reg_col_offt;
            char const * start_ptr = regs_repr + offt;
            char * endptr = NULL;

            errno = 0;
            regs[reg] = strtoul(start_ptr, &endptr, 16);

            if(errno != 0)
            {
               perror("strtoul");
               exit(1);
            }

            // make sure we only parsed the value
            assert(endptr - start_ptr == 16);

        }
    }

    return regs_repr + 8 * parse_reg_line_len;
}




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


    /*
     * Currently:
     * 1. read the response from QEMU, drop the unused data, copy register representation
     *    in a buffer, then parse the buffer, then do taint propagation
     * 2. Improvement 1: do the parse and taint in another thread so that we can give
     *    back control of main thread to QEMU. E.g. push buffer to a (blocking?) queue
     *    and return. Another thread picks up buffer and processes.
     */ 


    // make new region to pass it to another thread
    size_t const all_regs_string_max_len = 4095; //FIXME: what is the max size?
    char * all_regs_string = malloc((all_regs_string_max_len + 1) * sizeof(char));
    memset(all_regs_string, 0, all_regs_string_max_len + 1);

    get_regs_repr(all_regs_string_max_len, all_regs_string);


    // Parse the integer and fp registers (as uint32)

    uint32_t xreg[32] = {0};
    uint32_t freg[32] = {0};

    char const * x_regs_repr_start = all_regs_string;
    char const * fp_regs_repr_start = parse_reg_repr(x_regs_repr_start, xreg);
    char const * parsed_block_end = parse_reg_repr(fp_regs_repr_start, freg);

    for(int reg = 0 ; reg < 32 ; reg++)
    {
        printf("x%d=%" PRIx32 "  ", reg, xreg[reg]);
        if (reg % 4 == 3) printf("\n");
    }


    for(int reg = 0 ; reg < 32 ; reg++)
    {
        printf("f%d=%" PRIx32 "  ", reg, freg[reg]);
        if (reg % 4 == 3) printf("\n");
    }


}


struct InsnData
{
    char * disas;
    unsigned char * opcode;
    size_t opcode_size;
};

static void vcpu_insn_exec(unsigned int vcpu_index, void *userdata)
{
    struct InsnData * ins_data = (struct InsnData*)userdata;
    
    printf("(");
    for(int i = 0 ; i < ins_data->opcode_size ; i++)
    {
        printf("%x ", ins_data->opcode[i]);
    }
    printf(") %s\n", ins_data->disas);
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

        void * data_mem = NULL;

        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, data_mem);



        void const * opcode_ptr = qemu_plugin_insn_data(insn);
        size_t opcode_size = qemu_plugin_insn_size(insn);

        // FIXME: use g_hash_table and/or g_new (refcount) to keep track
        // of allocated memory.
        struct InsnData * ins_data = malloc(sizeof(struct InsnData));

        // disas: allocated string
        ins_data->disas = qemu_plugin_insn_disas(insn);
        ins_data->opcode = malloc(opcode_size);
        ins_data->opcode_size = opcode_size;

        memcpy(ins_data->opcode, opcode_ptr, opcode_size);

        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                         QEMU_PLUGIN_CB_NO_REGS, (void*)ins_data);
    }
}



// TODO: add plugin clos
// free ressources
static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    if(close(hmp_sock_fd) < 0){
        perror("Error closing HMP socket connection");
        exit(1);
    }
}


QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    
    fprintf(stderr, "Connecting to monitor on unix socket: %s\n", HMP_UNIX_SOCKET);

    hmp_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(hmp_sock_fd < 0)
    {
        perror("Failed to create socket\n");
        exit(1);
    }

    struct sockaddr_un sock_name = {
        .sun_family = AF_UNIX,
        .sun_path = HMP_UNIX_SOCKET
    };

    if (connect(hmp_sock_fd, (struct sockaddr *)&sock_name, sizeof(sock_name)) < 0)
    {
        perror("Failed to connect the socket");
        exit(1);
    }


    return 0;
}


