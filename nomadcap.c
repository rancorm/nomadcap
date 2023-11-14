/*
*
* nomadcap.c [PCAP tool that aids in locating misconfigured network stacks]
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <pcap.h>

/* getopt friends */
extern char *optarg;
extern int optind, opterr, optopt;

#include "nomadcap.h"

void
nomadcap_exit(nomadcap_pack_t *pack, int code) {
    /* Clean up */
    if (pack->device) {
        free(pack->device);
    }

    exit(code);
}

int
nomadcap_interesting(nomadcap_pack_t *pack,
    unsigned char *packet,
    nomadcap_entry_t **hash_table) {
}

int
main(int argc, char *argv[]) {
    nomadcap_pack_t pack;
    nomadcap_entry_t *hash_table[NOMADCAP_TABLE_SIZE];
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int c = -1;

    /* Init */
    pack.device = NULL;
    pack.filter = NOMADCAP_FILTER;
    pack.threshold = NOMADCAP_THRESHOLD;
    pack.flags = NOMADCAP_FLAGS_NONE;

    /* Parse command line argumemnts */
    while ((c = getopt(argc, argv, NOMADCAP_OPTS)) != -1) {
        switch (c) {
            case 'n':
                pack.threshold = atoi(optarg);
                break;
            case 'i':
                pack.device = strdup(optarg);
                break;
            case 'v':
                pack.flags |= NOMADCAP_FLAGS_VERB;
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-n #] [-i intf] [-hv]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    /* Leave it to libpcap to find an interface */
    if (pack.device == NULL) {
        /* Find all available network interfaces */
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
            nomadcap_exit(&pack, EXIT_FAILURE);
        }

        /* No interfaces, print an error message and exit */
        if (alldevs == NULL) {
            fprintf(stderr, "No interfaces found\n");
            nomadcap_exit(&pack, EXIT_FAILURE);
        }

        /* Copy device name of first found device */
        pack.device = strdup(alldevs[0].name);

        /* Free the list of interfaces */
        pcap_freealldevs(alldevs);
    }

    printf("Frame threshold: %d\n", pack.threshold);
    printf("Listening on: %s\n", pack.device);

    /* Verbose details.. */
    if (pack.flags & NOMADCAP_FLAGS_VERB) {
        printf("Filter: %s\n", NOMADCAP_FILTER);
    }

    nomadcap_exit(&pack, EXIT_SUCCESS);
}