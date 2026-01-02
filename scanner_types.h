

typedef enum {SCAN_NONE,SCAN_SYN,SCAN_TCP,SCAN_PING} SCAN_TYPE;

typedef struct {
    int sock;
    sockaddr_in;
} SocketConfig;
typedef struct {
    int epfd;
    struct epoll_event event;
    struct epoll_event* events;
} Epoll_Config;

typedef struct {


    SCAN_TYPE Scan_type;
} Scanner;