#include "scanner_types.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
void cleanup(Scanner* scanner_ptr){
    fprintf(stderr,"%d\n",scanner_ptr->port_alloc.port_ptr[0]);
    if (scanner_ptr->port_alloc.port_ptr){
        perror("1");
        free(scanner_ptr->port_alloc.port_ptr);
        scanner_ptr->port_alloc.port_ptr=NULL;
    }
    if (scanner_ptr->sk_config.tcp_sock > 0){
        close(scanner_ptr->sk_config.tcp_sock);
    }
    if (scanner_ptr->sk_config.udp_sock > 0){
        close(scanner_ptr->sk_config.udp_sock);
    }
    if (scanner_ptr->ep_config.epfd > 0){
        close(scanner_ptr->ep_config.epfd);
    }
    if (scanner_ptr->ep_config.events){
        perror("2");
        free(scanner_ptr->ep_config.events);
        scanner_ptr->ep_config.events=NULL;
    }
    if (scanner_ptr->probes){
        perror("3");
        free(scanner_ptr->probes);
    }
}