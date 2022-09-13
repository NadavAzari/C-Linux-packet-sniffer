#include <stdio.h>
#include <stdlib.h>
#include "../h files/sniffer.h"

#define MAX_SIZE 65536


int main(int argc, char* argv[]) {

    char* interface = argv[1];
    Sniff(interface);
    return 0;
}