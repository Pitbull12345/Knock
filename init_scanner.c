#include "init_scanner.h"
#include "scanner_types.h"
#include "cleanup.h"

#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <fcntl.h>



int parse_ports(char* port_string,Scanner* scanner_ptr){
    scanner_ptr->port_alloc.offset=0;
    char* end_ptr;
    char* token;
    char* ports=strdup(port_string);
    if (!ports){
        fprintf(stderr,"init_scanner.c: error: Allocating Mem for ports\n");
        return ERR_ALLOCATING_MEM;
    }
    token=strtok(ports,",");
    scanner_ptr->port_alloc.port_ptr=malloc(24*sizeof(int));
    if (!scanner_ptr->port_alloc.port_ptr){
        fprintf(stderr,"init_scanner.c: error: Allocating Mem for port_ptr\n");
        return ERR_ALLOCATING_MEM;
    }
    scanner_ptr->port_alloc.size=24;
    while (token!=NULL){
        for (int i=0;token[i] != '\0';i++){
            if (isdigit((unsigned char)token[i])){
                continue;
            } else {
                free(ports);
                return ERR_INVALID_ARGS;
            }
        }
        long val=strtol(token,&end_ptr,10);
        if (*end_ptr != '\0' || val > 65535 || val < 1){
            fprintf(stderr,"%ld is not in the valid port range of 1-65535",val);
            free(ports);
            return ERR_INVALID_ARGS;
        }
        if (scanner_ptr->port_alloc.offset < scanner_ptr->port_alloc.size){
            *(scanner_ptr->port_alloc.port_ptr+scanner_ptr->port_alloc.offset)=(int)val;
            scanner_ptr->port_alloc.offset+=1;
        } else{
            scanner_ptr->port_alloc.size=scanner_ptr->port_alloc.size*2;
            int* temp_ptr=realloc(scanner_ptr->port_alloc.port_ptr,(scanner_ptr->port_alloc.size* sizeof(int)));
            if (!temp_ptr){
                fprintf(stderr,"init_scanner.c: error: Allocating mem for temp_ptr\n");
                free(ports);
                return ERR_ALLOCATING_MEM;
            }
            scanner_ptr->port_alloc.port_ptr=temp_ptr;
            *(scanner_ptr->port_alloc.port_ptr+scanner_ptr->port_alloc.offset)=(int)val;
            scanner_ptr->port_alloc.offset+=1;
        }
        token=strtok(NULL,",");
    }
    free(ports);
    return 0;
}
int valid_args(int argc,char* argv[],Scanner* scanner_ptr){
    int opt;
    while ((opt=getopt(argc,argv,"s:T:p:")) != -1){
        switch(opt){
            case 's':
                if (optarg[0] != 'S' && optarg[0] != 'P' && optarg[0] != 'T'){
                    fprintf(stderr,"%c is not a valid Scan Type:(S=SYN,T=TCP,P=PING), ex. -sS \n",optarg[0]);
                    return ERR_INVALID_ARGS;
                }
                break;
            case 'T':
                int digit=optarg[0]-'0';
                if (digit > 5 || digit < 1){
                    fprintf(stderr,"%d is not a valid Timing Type:(1,2,3,4,5), ex -T1 or T4 \n",digit);
                    return ERR_INVALID_ARGS;
                }
                break;
            case 'p':
                if (optarg==NULL || optarg[0] == '/' || optarg[0]=='0'){
                    fprintf(stderr,"-p needs to be followed by ports like -p 40,354,80 \n");
                    return ERR_INVALID_ARGS;
                }
                break;
        } 
    }
    if (argc > optind+1){
        fprintf(stderr,"The IP must be the last argument or there cant be mulitple NON Argument Strings\n");
        return ERR_INVALID_ARGS;
    }
    struct in_addr temp_ipv4={0};
    if (inet_pton(AF_INET,argv[optind],&temp_ipv4)!=1){
        fprintf(stderr,"Not a Valid IP\n");
        return ERR_INVALID_ARGS;
    }
    scanner_ptr->target_ip=argv[optind]; 
    //TODO: IMPLEMENT IPV6

    return 0;
}
int parse_args(int argc,char* argv[],Scanner* scanner_ptr){
    int opt;
    while ((opt=getopt(argc,argv,"s:T:p:")) != -1){
        switch (opt){
            case 's':
                if (optarg[0]=='S'){scanner_ptr->scan_type=SCAN_SYN;}
                else if (optarg[0]=='P'){scanner_ptr->scan_type=SCAN_PING;}
                else if (optarg[0]=='T'){scanner_ptr->scan_type=SCAN_TCP;}
                break;
            case 't':
                if (optarg[0]=='1'){scanner_ptr->timing=TIME_1;}
                else if (optarg[0]=='2'){scanner_ptr->timing=TIME_2;}
                else if (optarg[0]=='3'){scanner_ptr->timing=TIME_3;}
                else if (optarg[0]=='4'){scanner_ptr->timing=TIME_4;}
                else if (optarg[0]=='5'){scanner_ptr->timing=TIME_5;}
                break;
            case 'p':
                if (parse_ports(optarg,scanner_ptr)){
                    fprintf(stderr,"%s are not valid ports",optarg);
                    return ERR_INVALID_ARGS;
                }
                break;
        }
    }
    return 0;
}
int validate_scanner_config(Scanner* scanner_ptr){
    if (scanner_ptr->scan_type==0){
        fprintf(stderr,"Did Not Specify Scan Type\n");
        return ERR_INVALID_ARGS;
    }
    if (scanner_ptr->timing==0){
        scanner_ptr->timing=TIME_2;
    }
    if (!scanner_ptr->port_alloc.port_ptr){
        int* temp=malloc(sizeof(int)*24);
        if (!temp){
            fprintf(stderr,"init_scanner: error : Allocating Mem for Default Ports\n");
            return ERR_ALLOCATING_MEM;
        }
        int def_ports[24]={21,22,23,25,53,67,68,69,80,110,119,123,137,138,139,143,161,389,443,445,465,587,993,995};
        for (int i=0;i < 24;i++){
            temp[i]=def_ports[i];
        }
        scanner_ptr->port_alloc.port_ptr=temp;
        scanner_ptr->port_alloc.size=24;
    }
    return 0;
}
void help_print(){
    fprintf(stderr,"        Welcome To Knock\n");
    fprintf(stderr,"To Get Started There is a Couple Commands ill Show You\n");
    fprintf(stderr,"-------------------------------------------------------\n");
    fprintf(stderr,"Use -T(num) where num is 1-5. 5 is the Slowest, 1 is the fastest\n");
    fprintf(stderr,"Use -sS for Syn Scan, -sT for TCP Scan, and -sP for Ping Scan\n");
    fprintf(stderr,"Use -p to specify ports like, -p 445,80 or -p 21,22,23\n\n");
    fprintf(stderr,"Ex. ./Knock -sS -T5 192.168.1.1\n\n");
}
int non_block(int sock){
    int flags=fcntl(sock,F_GETFL,0);
    if (flags==-1) return 1;
    flags |= O_NONBLOCK;
    return fcntl(sock,F_SETFL,flags);
}
int init_socket_config(Scanner* scanner_ptr){
    int tcp_sock=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
    int udp_sock=socket(AF_INET,SOCK_RAW,IPPROTO_UDP);
    if (tcp_sock < 0){
        perror("init_scanner.c: error: Error Creating TCP Socket\n");
        return ERR_SOCKET;}
    if(udp_sock < 0){
        perror("init_scanner.c: error: Error Creating UDP Socket\n");
        return ERR_SOCKET;
    }
    int one=1;
    if (setsockopt(tcp_sock,IPPROTO_IP,IP_HDRINCL,&one,sizeof(one))){
        perror("init_scanner.c: error: Error Setting Sock Opt HDR INCL for TCP\n");
        return ERR_SOCKET;}
    if(setsockopt(udp_sock,IPPROTO_IP,IP_HDRINCL,&one,sizeof(one))){
        perror("init_scanner.c: error: Error Setting SOck opt HDR INCL For UDP\n");
        return ERR_SOCKET;
    }
    if (non_block(tcp_sock)){
        perror("init_scanner.c: error: Setting NonBlock on TCP Socket\n");
        return ERR_SOCKET;}
    if (non_block(udp_sock)){
        perror("init_scanner.c: error: Setting NonBlock on UDP Socket\n");
        return ERR_SOCKET;
    }
    memset(&scanner_ptr->sk_config.addr,0,sizeof(struct sockaddr_in));
    scanner_ptr->sk_config.tcp_sock=tcp_sock;
    scanner_ptr->sk_config.udp_sock=udp_sock;
    scanner_ptr->sk_config.addr.sin_family=AF_INET;
    inet_pton(AF_INET,scanner_ptr->target_ip,&scanner_ptr->sk_config.addr.sin_addr.s_addr);
    return 0;
}
int init_epoll_config(Scanner* scanner_ptr){
    int epfd=epoll_create1(0);
    EpollConfig* epcf_ptr=&scanner_ptr->ep_config;
    epcf_ptr->ev_tcp.events=EPOLLIN;
    epcf_ptr->ev_tcp.data.fd=scanner_ptr->sk_config.tcp_sock;
    epcf_ptr->ev_udp.events=EPOLLIN;
    epcf_ptr->ev_udp.data.fd=scanner_ptr->sk_config.udp_sock;
    if (epoll_ctl(epfd,EPOLL_CTL_ADD,scanner_ptr->sk_config.tcp_sock,&epcf_ptr->ev_tcp) < 0){
        perror("init_scanner.c: error: Error Epolling Config for TCP SOCK\n");
        return ERR_EPOLL;
    }
    if (epoll_ctl(epfd,EPOLL_CTL_ADD,scanner_ptr->sk_config.udp_sock,&epcf_ptr->ev_udp) < 0){
        perror("init_scanner.c: error: Error Epolling Config for UDP SOCK\n");
        return ERR_EPOLL;
    }
    epcf_ptr->events=malloc(sizeof(struct epoll_event)* 32);
    if (!epcf_ptr->events){
        perror("init_scanner.c: error: Error Creating Mem for Events\n");
        return ERR_ALLOCATING_MEM;
    }


    return 0;
}


int init_scanner(int argc,char* argv[],Scanner* scanner_ptr){
    if (argc==1){help_print(); return ERR_INVALID_ARGS;}
    if (valid_args(argc,argv,scanner_ptr)){return ERR_INVALID_ARGS;}
    if (parse_args(argc,argv,scanner_ptr)){cleanup(scanner_ptr);return ERR_PARSE;}
    if (validate_scanner_config(scanner_ptr)){cleanup(scanner_ptr);return ERR_INVALID_ARGS;}
    if (init_socket_config(scanner_ptr)){cleanup(scanner_ptr); return ERR_SOCKET;}
    if (init_epoll_config(scanner_ptr)){cleanup(scanner_ptr);return ERR_EPOLL;}

    return 0;
}