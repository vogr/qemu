#pragma once


void taint_monitor_loop(char const * taintsock_path);
void * taint_monitor_loop_pthread(void *);