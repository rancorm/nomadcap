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

#include "nomadcap.h"

/* Global termination control */
int loop = 1;

/* IEEE OUI data */
nomadcap_oui_t **ouis = NULL;

int
nomadcap_loadoui(char *ouipath) {
    /* Local IEEE OUI via CSV file (if found) */

    return 0;
}

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
    bpf_u_int32 netmask_hbo, localnet_hbo;
    bpf_u_int32 netaddr, netaddr_hbo;

    /* Convert to host byte order */
    netmask_hbo = ntohl(pack->netmask);
    localnet_hbo = ntohl(pack->localnet);
    
    /* Perform AND operation between IP address and the local netmask */
    netaddr_hbo = htonl(*((bpf_u_int32 *)arp->arp_spa));
    netaddr = netaddr_hbo & netmask_hbo;

    /* Check if ARP was meant for the local network */
    return (netaddr == localnet_hbo);
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
    /* Banner*/
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

void
nomadcap_output(nomadcap_pack_t *pack, struct ether_arp *arp) {          
    /* Format: <Sender IP> [<Sender MAC>] is looking for <Target IP> */

    /* Sender IP */
    nomadcap_aprint(arp->arp_spa, 4, '.', 0); 

    /* Sender MAC */
    printf(" [");
    nomadcap_aprint(arp->arp_sha, ETH_ALEN, ':', 1);
    printf("] is looking for ");

    /* Target IP */
    nomadcap_aprint(arp->arp_tpa, 4, '.', 0);

    printf("\n");
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
    int c = -1, is_local = -1;

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

    NOMADCAP_STDERR(pack, "Flags: 0x%08x\n", pack.flags);

    /* Load IEEE OUI data */
    if (NOMADCAP_FLAG(pack, OUI)) {
        NOMADCAP_STDERR(pack, "Loading OUI data from %s...\n", NOMADCAP_OUI_FILEPATH);

        nomadcap_loadoui(NOMADCAP_OUI_FILEPATH);
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

    /* Current state */    
    printf("Listening on: %s\n", pack.device);

    /* Verbose details.. */
    if (NOMADCAP_FLAG(pack, VERB)) {
        /* Convert local network and mask to human readable strings */
        inet_ntop(AF_INET, &pack.localnet, localnet_str, sizeof(localnet_str));
        inet_ntop(AF_INET, &pack.netmask, netmask_str, sizeof(netmask_str));

        printf("Local network: %s\n", localnet_str);
        printf("Network mask: %s\n", netmask_str);
        printf("Filter: %s\n", NOMADCAP_FILTER);
    }

    /* Loop */
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
                    NOMADCAP_STDERR(pack, "Non ARP request, ignoring...\n");

                    continue;
                }

                /* Check for ARP probe - ARP sender MAC is all zeros */
                if (memcmp(arp->arp_sha, NOMADCAP_NONE, arp->ea_hdr.ar_hln) == 0 &&
                    NOMADCAP_FLAG_NOT(pack, PROBES)) {
                    NOMADCAP_STDERR(pack, "ARP probe, ignoring...\n");

                    continue;
                }

                /* Check for ARP announcement - ARP sender and target IP match */
                if (memcmp(arp->arp_spa, arp->arp_tpa, arp->ea_hdr.ar_pln) == 0 &&
                    NOMADCAP_FLAG_NOT(pack, ANNOUC)) {
                    NOMADCAP_STDERR(pack, "ARP announcement, ignoring...\n");

                    continue;
                }

                /* Check if ARP request is not local */
                is_local = nomadcap_localnet(&pack, arp);

                if (is_local == 0 || NOMADCAP_FLAG(pack, ALLNET)) {
                    /* Output ARP results */
                    nomadcap_output(&pack, arp);
                } else {
                    NOMADCAP_STDERR(pack, "Local traffic, ignoring...\n");
                }
            }
        }
    }

    /* Who doesn't love statistics (verbose only) */
    if (NOMADCAP_FLAG(pack, VERB)) {
        if (pcap_stats(pack.p, &ps) == -1) {
            NOMADCAP_STDERR(pack, "pcap_stats: %s\n", pcap_geterr(pack.p));
        } else {
            fprintf(stderr, "\nPackets received: %d\n", ps.ps_recv);
            fprintf(stderr, "Packets dropped: %d\n", ps.ps_drop);
        }
    }

    nomadcap_exit(&pack, EXIT_SUCCESS);
}