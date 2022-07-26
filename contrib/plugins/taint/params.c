#include "params.h"

uint8_t * shadow_mem = 0;
uint64_t shadow_regs[32] = {0};

pthread_mutex_t shadow_lock = {0};