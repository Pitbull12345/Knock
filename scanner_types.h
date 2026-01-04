#ifndef SCANNER_TYPES_H
#define SCANNER_TYPES_H


#include <stdint.h>
#include <sys/epoll.h>
#include <netinet/in.h>

#define ERR_INVALID_ARGS 101
#define ERR_PARSE 102
#define ERR_ALLOCATING_MEM 103
#define ERR_SOCKET 104
#define ERR_EPOLL 105
#define ERR_RUNNING_SCAN 106


typedef enum {TIME_NONE=0,TIME_1,TIME_2,TIME_3,TIME_4,TIME_5} TIME_SETTINGS;
typedef enum {SCAN_NONE=0,SCAN_SYN,SCAN_TCP,SCAN_PING} SCAN_TYPE;
typedef enum {PROBE_UNSENT=0,PROBE_PENDING,PROBE_CLOSED,PROBE_OPEN} PORT_STATUS;

typedef struct {
    int tcp_sock;
    int udp_sock;
    struct sockaddr_in addr;
} SocketConfig;

typedef struct {
    int epfd;
    struct epoll_event ev_tcp;
    struct epoll_event ev_udp;
    struct epoll_event *events;
} EpollConfig;

typedef struct{
    int* port_ptr;
    int size;
    int offset;
} Port_Alloc;

typedef struct{
    PORT_STATUS port_status;
    int port;
} Probe;

typedef struct {
    Probe* probes;
    Port_Alloc port_alloc;
    EpollConfig ep_config;
    SocketConfig sk_config;
    char* target_ip;
    TIME_SETTINGS timing;
    SCAN_TYPE scan_type;
} Scanner;

#endif