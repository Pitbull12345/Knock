#include "scanner_types.h"
#include "cleanup.h"

#include <stdio.h>
#include <stdlib.h>

int create_probes(Scanner* scanner_ptr){
    scanner_ptr->probes=malloc(sizeof(Probe)*scanner_ptr->port_alloc.size);
    if (!scanner_ptr->probes){
        perror("run_scan.c: error: Error Allocating Mem for Probes\n");
        return ERR_ALLOCATING_MEM;
    }
    int i;
    for (i=0;i < scanner_ptr->port_alloc.size;i++){
        scanner_ptr->probes[i].port=scanner_ptr->port_alloc.port_ptr[i];
    }
    printf("Created: %d Probes\n",i);

    return 0;
}




int run_scan(Scanner* scanner_ptr){
    //1. Create Probes, 2. Create TCP and UDP Packets 3. Send 4. Wait for Response
    if (create_probes){cleanup(scanner_ptr);return ERR_RUNNING_SCAN;}
    return 0;
}