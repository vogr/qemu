#include "params.h"

uint8_t * shadow_mem = 0;
size_t shadow_mem_size = 0;

target_ulong shadow_regs[32] = {0};

pthread_mutex_t shadow_lock = {0};