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

/* PCAP */
#include <pcap.h>

/* Ethernet and ARP */
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

/* getopt friends */
extern char *optarg;
extern int optind, opterr, optopt;

#include "nomadcap.h"

/* Global termination control */
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
nomadcap_localnet(nomadcap_pack_t *pack, struct ether_arp *arp) {
    /* Check if ARP is for the local network */

    return 0;
}

void
nomadcap_cleanup(int signno) {
    loop = 0;

    fprintf(stderr, "Interrupt signal caught...\n");
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

void
nomadcap_aprint(uint8_t *addr, int size, char sep, int hex) {
    for (int i = 0; i < size; i++) {
        /* Output in hex or decimal */
        if (hex) {
            printf("%02x", addr[i]);
        } else {
            printf("%d", addr[i]);
        }

        /* Output seperator */
        if (i < size - 1) {
            printf("%c", sep);
        }
    }
}

void
nomadcap_usage(char *progname) {
    printf("%s\n", NOMADCAP_BANNER);
    printf("Usage: %s [-i intf] [-OApahvV]\n\n", progname);

    printf("\t-i [intf]\t\tInterface\n");
    printf("\t-O\t\tOUI to organization lookup\n");
    printf("\t-A\t\tAll networks\n");
    printf("\t-p\t\tProcess ARP probes\n");
    printf("\t-a\t\tProcess ARP announcements\n");
    printf("\t-v\t\tVerbose mode\n");
    printf("\t-V\t\tVersion\n");

    printf("\nAuthor: %s\n", NOMADCAP_AUTHOR);
}

int
main(int argc, char *argv[]) {
    nomadcap_pack_t pack;
    pcap_if_t *devs;
    struct pcap_stat ps;
    struct ether_header *eth;
    struct ether_arp *arp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char localnet_str[INET_ADDRSTRLEN];
    char netmask_str[INET_ADDRSTRLEN];
    uint8_t *pkt;
    int c = -1;

    /* Init */
    pack.device = NULL;
    pack.p = NULL;
    pack.filter = NOMADCAP_FILTER;
    pack.flags = NOMADCAP_FLAGS_NONE;

    /* Parse command line argumemnts */
    while ((c = getopt(argc, argv, NOMADCAP_OPTS)) != -1) {
        switch (c) {
            case 'O':
                pack.flags |= NOMADCAP_FLAGS_OUI;
                break;
            case 'A':
                pack.flags |= NOMADCAP_FLAGS_ALLNET;
                break;
            case 'p':
                pack.flags |= NOMADCAP_FLAGS_PROBES;
                break;
            case 'a':
                pack.flags |= NOMADCAP_FLAGS_ANNOUC;
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
            case 'h':
                nomadcap_usage(argv[0]);
                nomadcap_exit(&pack, EXIT_SUCCESS);
            default: /* '?' */
                exit(EXIT_FAILURE);
        }
    }

    /* Leave it to libpcap to find an interface */
    if (pack.device == NULL) {
        /* Find all available network interfaces */
        if (pcap_findalldevs(&devs, errbuf) == -1) {
            fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
            nomadcap_exit(&pack, EXIT_FAILURE);
        }

        /* No interfaces, print an error message and exit */
        if (devs == NULL) {
            fprintf(stderr, "No interfaces found\n");
            nomadcap_exit(&pack, EXIT_FAILURE);
        }

        /* Copy device name of first found device */
        pack.device = strdup(devs[0].name);

        /* Free the list of interfaces */
        pcap_freealldevs(devs);
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

    /* Look up local network and mask */
    if (pcap_lookupnet(pack.device, &pack.localnet, &pack.netmask, errbuf) == -1) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        nomadcap_exit(&pack, EXIT_FAILURE);
    }

    /* Comile filter into BPF program */
    if (pcap_compile(pack.p, &pack.code, pack.filter, 1, pack.netmask) == -1) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(pack.p));
        nomadcap_exit(&pack, EXIT_FAILURE);
    }

    /* Set program as filter */
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

    /* Convert local network and mask to human readable strings */
    inet_ntop(AF_INET, &pack.localnet, localnet_str, sizeof(localnet_str));
    inet_ntop(AF_INET, &pack.netmask, netmask_str, sizeof(netmask_str));

    /* Current state */    
    printf("Listening on: %s\n", pack.device);

    /* Verbose details.. */
    if (NOMADCAP_FLAG(pack, VERB)) {
        printf("Local network: %s\n", localnet_str);
        printf("Network mask: %s\n", netmask_str);
        printf("Filter: %s\n", NOMADCAP_FILTER);
    }

    /* Initialize hash table and loop */
    while(loop) {
        pkt = (uint8_t *)pcap_next(pack.p, &pack.ph);

        /* Catch timer expiring with no data in packet buffer */
        if (pkt == NULL) continue;

        eth = (struct ether_header *)pkt;

        /* Cast packet to ARP header */
        arp = (struct ether_arp *)(pkt + sizeof(struct ether_header));

        /* Check if ARP header length is valid */
        if (pack.ph.caplen >= sizeof(struct ether_header) + sizeof(struct arphdr)) {
            /* Check for Ethernet broadcasts */
            if (memcmp(eth->ether_dhost, NOMADCAP_BROADCAST, ETH_ALEN) == 0) {
                /* Only looking for ARP requests */
                if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REQUEST) {
                    NOMADCAP_PRINTF(pack, "Non ARP request, ignoring...\n");

                    continue;
                }

                /* Check for ARP probe - ARP sender MAC is all zeros */
                if (memcmp(arp->arp_sha, NOMADCAP_NONE, arp->ea_hdr.ar_hln) == 0) {
                    if (NOMADCAP_FLAG(pack, VERB)) {
                        fprintf(stderr, "ARP probe, ignoring...\n"); 
                    }

                    continue;
                }

                /* Check for ARP announcement - ARP sender and target IP match */
                if (memcmp(arp->arp_spa, arp->arp_tpa, arp->ea_hdr.ar_pln) == 0) {
                    if (NOMADCAP_FLAG(pack, VERB)) {
                        fprintf(stderr, "ARP announcement, ignoring...\n");
                    }

                    continue;
                }

                /* Check if ARP request is not local */
                /* Match arp_spa(uint8_t[4]) is on localnet (bpf_u_int32) */

                /* <Sender IP> [<Sender MAC>] is looking for <Target IP> */
                nomadcap_aprint(arp->arp_spa, 4, '.', 0); 

                printf(" [");
                nomadcap_aprint(arp->arp_sha, ETH_ALEN, ':', 1);
                printf("] is looking for ");

                nomadcap_aprint(arp->arp_tpa, 4, '.', 0);

                printf("\n");
            }
        }
    }

    /* Who doesn't love statistics (verbose only) */
    if (NOMADCAP_FLAG(pack, VERB)) {
        if (pcap_stats(pack.p, &ps) == -1) {
            NOMADCAP_PRINTF(pack, "pcap_stats: %s\n", pcap_geterr(pack.p));
        } else {
            fprintf(stderr, "\nPackets received by libpcap:\t%6d\n", ps.ps_recv);
            fprintf(stderr, "Packets dropped by libpcap:\t%6d\n", ps.ps_drop);
        }
    }

    nomadcap_exit(&pack, EXIT_SUCCESS);
}