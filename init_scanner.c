#include "init_scanner.h"
#include "scanner_types.h"

#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

static int valid_args(int argc,char* argv[]);
static int parse_args(int argc,char* argv[],Scanner* scanner_ptr); 

int parse_ports(char* port_string){
    char* ports=strdup(port_string,sizeof(port_string));
    int results[];
    char* end_ptr;
    char* token;

    token=strtok(ports,",");
    scanner_ptr->port_ptr=malloc(24*sizeof(int));
    while (token!=NULL){
        for (int i=0;token[i] != '\0';i++){
            if (isdigit((unsigned char)token[i])){
                continue;
            } else {
                return ERR_INVALID_ARGS;
            }
        }
        long val=strtol(token,&end_ptr,10);
        

        
    }
}
int valid_args(int argc,char* argv[]){
    int opt;
    while (opt=getopt(argc,argv,"s:T:p:") != -1){
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
    //TODO: IMPLEMENT IPV6

    return 0;
}
int parse_args(int argc,char* argv[],Scanner* scanner_ptr){
    int opt;
    while (opt=getopt(argc,argv,"s:T:p:") != -1){
        switch (opt){
            case 's':
                if (optarg[0]=='S'){scanner_ptr->scan_type=SCAN_SYN}
                else if (optarg[0]=='P'){scanner_ptr->scan_type=SCAN_PING}
                else if (optarg[0]=='T'){scanner_ptr->scan_type=SCAN_TCP}
                break;
            case 't':
                if (optarg[0]=='1'){scanner_ptr->Timing=TIME_1}
                else if (optarg[0]=='2'){scanner_ptr->Timing=TIME_2}
                else if (optarg[0]=='3'){scanner_ptr->Timing=TIME_3}
                else if (optarg[0]=='4'){scanner_ptr->Timing=TIME_4}
                else if (optarg[0]=='5'){scanner_ptr->Timing=TIME_5}
                break;
            case 'p':
                if (parse_ports(optarg)){
                    fprintf(stderr,"%s are not valid ports",optarg);
                    return ERR_INVALID_ARGS;
                }
                break;
        }
    }
    return 0;
}
int verify_args(Scanner* scanner_ptr){

}





int init_scanner(int argc,char* argv[],Scanner* scanner_ptr){
    if (valid_args(argc,argv)){return ERR_INVALID_ARGS;}
    if (parse_args(argc,argv,scanner_ptr)){return ERR_PARSE;}
    if (validate_scanner(scanner_ptr)){return ERR_INVALID_ARGS;}
    
    return 0;
}