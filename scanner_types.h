#ifndef SCANNER_TYPES_H
#define SCANNER_TYPES_H


#include <stdint.h>
#include <sys/epoll.h>
#include <netinet/in.h>

#define ERR_INVALID_ARGS 101
#define ERR_PARSE 102

typedef enum {TIME_1,TIME_2,TIME_3,TIME_4,TIME_5} TIME_SETTINGS;
typedef enum {SCAN_NONE,SCAN_SYN,SCAN_TCP,SCAN_PING} SCAN_TYPE;
typedef enum {PROBE_UNSENT,PROBE_PENDING,PROBE_CLOSED,PROBE_OPEN} PORT_STATUS;

typedef struct {
    int sock;
    struct sockaddr_in addr;
} SocketConfig;

typedef struct {
    int epfd;
    struct epoll_event event;
    struct epoll_event *events;
} EpollConfig;
typedef struct{
    int* port_ptr;
    int size;
} Port_Alloc;

typedef struct {
    int* port_ptr;

    EpollConfig ep_config;
    SocketConfig sk_config;

    TIME_SETTINGS timing;
    SCAN_TYPE scan_type;
} Scanner;

#endif