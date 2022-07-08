#include "regs.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <errno.h>

#include <qemu-plugin.h>

#include "hmp.h"

/***
 * Accessing source registers values through the extended QEMU interface
 */
uint64_t get_one_reg_value_qemu(unsigned int vcpu_idx, char r)
{
    qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_idx);
    uint64_t values[1];
    int regs[1] = {r};
    qemu_plugin_get_register_values(cs, 1, regs, values);
    return values[0];
}




struct src_regs_values get_src_reg_values_qemu(unsigned int vcpu_idx, char rs1, char rs2)
{
    qemu_cpu_state cs = qemu_plugin_get_cpu(vcpu_idx);
    uint64_t values[2];
    int regs[2] = {rs1, rs2};
    qemu_plugin_get_register_values(cs, 2, regs, values);

    struct src_regs_values vals = {
        .v1 = values[0],
        .v2 = values[1]
    };

    return vals;
}



/***
 * Accessing source registers values through the QEMU HMP (ugly!)
 ***/


enum parse_state_t { PARSING_BEFORE, PARSING_COPYING, PARSING_LAST_COPY, PARSING_DONE };

#define GET_REGS_MAX_LINE_LEN 2047
static char get_regs_buf0[GET_REGS_MAX_LINE_LEN + 1] = {0};
static char get_regs_buf1[GET_REGS_MAX_LINE_LEN + 1] = {0};

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

    // Two buffers for reading, we will swap between the two as we recv
    // called "line" but not line-based, delimiter is first_line_prefix    
    size_t cur_line_len = 0;
    char * cur_line = get_regs_buf0;

    size_t next_line_len = 0;
    char * next_line = get_regs_buf1;

    // Position of the parser head in the current line or in all_regs_repr
    size_t parser_head = 0;

    // Length of the register state string representation in the buffer
    size_t all_regs_string_len = 0;

    static const char first_line_prefix[] = " x0/zero";
    static const size_t flp_s = sizeof(first_line_prefix) / sizeof(char) - 1;
    static const char last_line_prefix[] = "f28/ft8";
    static const size_t llp_s = sizeof(last_line_prefix) / sizeof(char) - 1;

    // FIXME: use glib regex instead of strcmp to find flp, llp and end of line (\R)

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
                    ssize_t n_recv = recv(hmp_sock_fd, cur_line + cur_line_len, GET_REGS_MAX_LINE_LEN - cur_line_len, 0);

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
}


// -1 for the NULL byte
static size_t const parse_reg_line_len = sizeof(" x0/zero  0000000000000000 x1/ra    00000000800001d6 x2/sp    0000000000000000 x3/gp    0000000000000000\r\n") / sizeof(char) - 1;
static size_t const parse_reg_line_offt = sizeof(" x0/zero  ") / sizeof(char) - 1;
static size_t const parse_reg_col_offt = sizeof("0000000000000000 x1/ra    ") / sizeof(char) - 1;
static uint64_t parse_one_reg(char const * regs_repr, int i_reg)
{
    /*
       Parse one register from the regs_repr
       Return the value as an uint32_t


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
    uint64_t v = strtoul(start_ptr, &endptr, 16);

    if(errno != 0)
    {
        perror("strtoul");
        exit(1);
    }

    // make sure we only parsed the value
    // 64bits, ie 8 bytes, ie 16 hex characters
    assert(endptr - start_ptr == 16);

    return v;
}



static char const * parse_reg_repr(char const * regs_repr, uint64_t * regs)
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
            // 64bits, ie 8 bytes, ie 16 hex characters
            assert(endptr - start_ptr == 16);

        }
    }

    return regs_repr + 8 * parse_reg_line_len;
}


#define ALL_REGS_STRING_MAX_LEN 4095

uint64_t get_one_reg_value(char r)
{
    static char all_regs_string[ALL_REGS_STRING_MAX_LEN + 1] = {0};
    get_regs_repr(ALL_REGS_STRING_MAX_LEN, all_regs_string);

    uint64_t v = parse_one_reg(all_regs_string, r);

    return v;
}




struct src_regs_values get_src_reg_values(char rs1, char rs2)
{
    static char all_regs_string[ALL_REGS_STRING_MAX_LEN + 1] = {0};
    get_regs_repr(ALL_REGS_STRING_MAX_LEN, all_regs_string);

    struct src_regs_values vals = {
        .v1 = parse_one_reg(all_regs_string, rs1),
        .v2 = parse_one_reg(all_regs_string, rs2)
    };

    return vals;
}