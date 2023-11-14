/*
*
* nomadcap.c [PCAP tool that aids in locating misconfigured network stacks]
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

extern char *optarg;
extern int optind, opterr, optopt;

#include "nomadcap.h"

int
main(int argc, char *argv[]) {
    int c = -1;
    char *device;

    /* Defaults */
    device = NOMADCAP_INTF;

    /* Parse command line argumemnts */
    while ((c = getopt(argc, argv, NOMADCAP_OPTS)) != -1) {
        switch (c) {
            case 'i':
                device = strdup(optarg);
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-i intf]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    printf("Listening on: %s\n", device);

    return 0;
}