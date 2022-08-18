#pragma once

#include <msgpack.h>

int taint_cmd_process_cmd_block(msgpack_unpacker * unp, msgpack_packer * pk);
