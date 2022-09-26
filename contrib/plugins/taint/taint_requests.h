#pragma once

#include <msgpack.h>

struct set_taint_range_params
{
    uint64_t start;
    uint64_t length;
    char t8;
};

int taint_cmd_process_cmd_block(msgpack_unpacker * unp, msgpack_packer * pk);

int taint_paddr_range_explicit(struct set_taint_range_params p);
