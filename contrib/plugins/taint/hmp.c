#include "hmp.h"

#include <stdlib.h>
#include <stdio.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int hmp_sock_fd = -1;


void open_hmp_socket(char const * sockpath)
{
    hmp_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(hmp_sock_fd < 0)
    {
        perror("Failed to create socket\n");
        exit(1);
    }

    struct sockaddr_un sock_name = {
        .sun_family = AF_UNIX,
    };
    snprintf(sock_name.sun_path, sizeof(sock_name.sun_path), "%s", sockpath);

    if (connect(hmp_sock_fd, (struct sockaddr *)&sock_name, sizeof(sock_name)) < 0)
    {
        perror("Failed to connect the socket");
        exit(1);
    }
}


void close_hmp_socket(void)
{
    if(close(hmp_sock_fd) < 0){
        perror("Error closing HMP socket connection");
        exit(1);
    }
}