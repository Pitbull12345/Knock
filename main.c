#include "scanner_types.h"
#include "init_scanner.h"

#include <stdio.h>


int main(int argc,char* argv[]){
    Scanner scanner;
    if (init_scanner(argc,argv,&scanner)){fprintf(stderr,"main: error: failed to intialize scanner\n"); return 1;}

    return 0;
}