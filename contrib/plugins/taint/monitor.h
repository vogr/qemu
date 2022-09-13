#pragma once

#include <sys/types.h>

int monitor_sendall(size_t size, char * buf);

void taint_monitor_loop(char const * taintsock_path);
void * taint_monitor_loop_pthread(void *);