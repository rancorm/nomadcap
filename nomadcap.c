/*
*
* nomadcap.c [PCAP tool that aids in locating misconfigured network stacks]
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include <pcap.h>

/* getopt friends */
extern char *optarg;
extern int optind, opterr, optopt;

#include "nomadcap.h"

int loop = 1;

void
nomadcap_exit(nomadcap_pack_t *pack, int code) {
    /* Clean up memory */
    if (pack->device) {
        free(pack->device);
    }

    /* Close capture device */
    if (pack->p) {
        pcap_close(pack->p);
    }

    exit(code);
}

int
nomadcap_interesting(nomadcap_pack_t *pack,
    unsigned char *packet,
    nomadcap_entry_t **hash_table) {
}

void
nomadcap_cleanup(int signno) {
    loop = 0;

    printf("Interrupt signal caught...\n");
}

int
nomadcap_signal(int signo, void (*handler)()) {
    struct sigaction sa;

    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(signo, &sa, NULL) == -1) {
        return -1;
    } else {
        return 1;
    }
}

int
main(int argc, char *argv[]) {
    nomadcap_pack_t pack;
    nomadcap_entry_t *hash_table[NOMADCAP_TABLE_SIZE];
    pcap_if_t *alldevs;
    struct pcap_stat ps;
    char errbuf[PCAP_ERRBUF_SIZE];
    int c = -1;

    /* Init */
    pack.device = NULL;
    pack.p = NULL;
    pack.filter = NOMADCAP_FILTER;
    pack.threshold = NOMADCAP_THRESHOLD;
    pack.flags = NOMADCAP_FLAGS_NONE;

    /* Parse command line argumemnts */
    while ((c = getopt(argc, argv, NOMADCAP_OPTS)) != -1) {
        switch (c) {
            case 't':
                pack.threshold = atoi(optarg);
                break;
            case 'i':
                pack.device = strdup(optarg);
                break;
            case 'v':
                pack.flags |= NOMADCAP_FLAGS_VERB;
                break;
            case 'V':
                printf("%s\n", NOMADCAP_VERSION);
                nomadcap_exit(&pack, EXIT_SUCCESS);
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-t #] [-i intf] [-hv]\n", argv[0]);
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

    /* Open capturing device */
    pack.p = pcap_open_live(pack.device,
        NOMADCAP_SNAPLEN,
        NOMADCAP_PROMISC,
        NOMADCAP_TIMEOUT,
        errbuf);

    if (pack.p == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        nomadcap_exit(&pack, EXIT_FAILURE);
    }

    /* Set filter */
    if (pcap_lookupnet(pack.device, &pack.localnet, &pack.netmask, errbuf) == -1) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        nomadcap_exit(&pack, EXIT_FAILURE);
    }

    if (pcap_compile(pack.p, &pack.code, pack.filter, 1, pack.netmask) == -1) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(pack.p));
        nomadcap_exit(&pack, EXIT_FAILURE);
    }

    if (pcap_setfilter(pack.p, &pack.code) == -1) {
        fprintf(stderr, "pcap_setfilter: %s\n", errbuf);
        nomadcap_exit(&pack, EXIT_FAILURE);
    }

    /* Check datalink */
    if (pcap_datalink(pack.p) != DLT_EN10MB) {
        fprintf(stderr, "pcap_datalink: Ethernet only, sorry.");
        nomadcap_exit(&pack, EXIT_FAILURE);
    }

    /* Catch signals */
    if (nomadcap_signal(SIGINT, nomadcap_cleanup) == -1) {
        fprintf(stderr, "Can't catch signal\n");
        nomadcap_exit(&pack, EXIT_FAILURE);
    }

    printf("Frame threshold: %d\n", pack.threshold);
    printf("Listening on: %s\n", pack.device);

    /* Verbose details.. */
    if (pack.flags & NOMADCAP_FLAGS_VERB) {
        printf("Filter: %s\n", NOMADCAP_FILTER);
    }

    /* Loop */
    for (; loop;);

    /* Stats */

    nomadcap_exit(&pack, EXIT_SUCCESS);
}