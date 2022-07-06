#pragma once

extern int hmp_sock_fd;

void open_hmp_socket(char const * sockpath);
void close_hmp_socket(void);