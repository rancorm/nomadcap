/*
 *
 * nomadcap.c [PCAP tool that aids in locating misconfigured network stacks]
 *
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* PCAP */
#include <pcap.h>

/* Ethernet and ARP */
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#ifdef USE_LIBCSV
#include <csv.h>
#endif /* USE_LIBCSV */

/* getopt friends */
extern char *optarg;

#include "nomadcap.h"

/* Global termination control */
int loop = 1;

int nomadcap_loadoui(char *ouipath) {
  /* Local IEEE OUI via CSV file (if found) */

  return 0;
}

void nomadcap_exit(nomadcap_pack_t *np, int code) {
  if (np) {
    /* Free strings */
    if (np->device)
      free(np->device);
    if (np->filename)
      free(np->filename);

    /* Close capture device */
    if (np->p)
      pcap_close(np->p);

    /* Free structure */
    free(np);
  }

  /* Exit with parameter supplied code */
  exit(code);
}

int nomadcap_localnet(nomadcap_pack_t *np, struct ether_arp *arp) {
  bpf_u_int32 netmask_hbo, localnet_hbo;
  bpf_u_int32 netaddr, netaddr_hbo;

  /* Convert to host byte order */
  netmask_hbo = ntohl(np->netmask);
  localnet_hbo = ntohl(np->localnet);

  /* Perform AND operation between IP address and the local netmask */
  netaddr_hbo = htonl(*((bpf_u_int32 *)arp->arp_spa));
  netaddr = netaddr_hbo & netmask_hbo;

  /* Check if ARP was meant for the local network */
  return (netaddr == localnet_hbo);
}

void nomadcap_cleanup(int signo) {
  loop = 0;

  fprintf(stderr, "Interrupt signal caught...\n");
}

void nomadcap_alarm(int signo) {
  loop = 0;

  fprintf(stderr, "Duration alarm caught...\n");
}

int nomadcap_signal(int signo, void (*handler)()) {
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

void nomadcap_aprint(uint8_t *addr, int size, char sep, int hex) {
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

void nomadcap_usage(nomadcap_pack_t *np) {
  /* Banner*/
  printf("%s v%s [%s]\n\n", np->pname, NOMADCAP_VERSION, NOMADCAP_BANNER);

  printf("Usage: %s [-i intf] [-f filename.pcap] [-d seconds] [-OApahvV]\n\n",
         np->pname);
  printf("\t-i <intf>\t\tCapture on interface <intf>\n");
  printf("\t-f <filename.pcap>\tOffline capture using <filename.pcap>\n");
  printf("\t-d <seconds>\tDuration of capture (seconds)\n");

#ifdef USE_LIBCSV
  printf("\t-O\t\t\tMAC OUI to organization\n");
#endif /* USE_LIBCSV */

  printf("\t-A\t\t\tAll networks (includes local traffic)\n");
  printf("\t-p\t\t\tProcess ARP probes\n");
  printf("\t-a\t\t\tProcess ARP announcements\n");
  printf("\t-v\t\t\tVerbose mode\n");
  printf("\t-V\t\t\tVersion\n");

  printf("\nAuthor: %s\n", NOMADCAP_AUTHOR);
}

void nomadcap_output(nomadcap_pack_t *np, struct ether_arp *arp) {
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

nomadcap_pack_t *nomadcap_init(char *pname) {
  nomadcap_pack_t *np;

  np = (nomadcap_pack_t *)malloc(sizeof(nomadcap_pack_t));

  if (np) {
    /* Set some sane defaults */
    np->device = NULL;
    np->p = NULL;
    np->filter = NOMADCAP_FILTER;
    np->flags = NOMADCAP_FLAGS_NONE;
    np->ouis = NULL;
    np->filename = NULL;

    np->duration = 0;

    /* Save program name */
    np->pname = pname;

    return np;
  }

  return NULL;
}

int main(int argc, char *argv[]) {
  nomadcap_pack_t *np;
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
  np = nomadcap_init(argv[0]);

  /* Bail if there are memory troubles */
  if (np == NULL) {
    fprintf(stderr, "nomadcap_init: alloc failure\n");
    exit(EXIT_FAILURE);
  }

  /* Parse command line argumemnts */
  while ((c = getopt(argc, argv, NOMADCAP_OPTS)) != -1) {
    switch (c) {
    case 'O':
      np->flags |= NOMADCAP_FLAGS_OUI;
      break;
    case 'A':
      np->flags |= NOMADCAP_FLAGS_ALLNET;
      break;
    case 'p':
      np->flags |= NOMADCAP_FLAGS_PROBES;
      break;
    case 'a':
      np->flags |= NOMADCAP_FLAGS_ANNOUNCE;
      break;
    case 'i':
      np->device = strdup(optarg);
      break;
    case 'f':
      np->flags |= NOMADCAP_FLAGS_FILE;
      np->filename = strdup(optarg);
      break;
    case 'd':
      /* User supplied duration or default */
      np->duration = optarg ? atoi(optarg) : NOMADCAP_DURATION;
      break;
    case 'v':
      np->flags |= NOMADCAP_FLAGS_VERB;
      break;
    case 'V':
      printf("%s\n", NOMADCAP_VERSION);
      nomadcap_exit(np, EXIT_SUCCESS);
    case 'h':
      nomadcap_usage(np);
      nomadcap_exit(np, EXIT_SUCCESS);
    default: /* '?' */
      exit(EXIT_FAILURE);
    }
  }

  /* Offline file capture */
  if (NOMADCAP_FLAG(np, FILE)) {
    NOMADCAP_STDOUT(np, "Loading capture file: %s\n", np->filename);

    np->p = pcap_open_offline(np->filename, errbuf);

    /* Catch PCAP open errors */
    if (np->p == NULL) {
      NOMADCAP_STDERR(np, "pcap_open_offline: %s\n", errbuf);
      nomadcap_exit(np, EXIT_FAILURE);
    }
  }

  /* Leave it to libpcap to find an interface */
  if (np->device == NULL) {
    NOMADCAP_STDOUT(np, "Looking for interface...\n");

    /* Find all available network interfaces */
    if (pcap_findalldevs(&devs, errbuf) == -1) {
      NOMADCAP_STDERR(np, "pcap_findalldevs: %s\n", errbuf);
      nomadcap_exit(np, EXIT_FAILURE);
    }

    /* No interfaces, print an error message and exit */
    if (devs == NULL) {
      NOMADCAP_STDERR(np, "No interfaces found\n");
      nomadcap_exit(np, EXIT_FAILURE);
    }

    /* Copy device name of first found device */
    np->device = strdup(devs[0].name);

    NOMADCAP_STDOUT(np, "Found interface: %s\n", np->device);

    /* Free the list of interfaces */
    pcap_freealldevs(devs);
  }

  NOMADCAP_STDOUT(np, "Flags: 0x%08x\n", np->flags);

  /* Load IEEE OUI data */
#ifdef USE_LIBCSV
  if (NOMADCAP_FLAG(np, OUI)) {
    NOMADCAP_STDOUT(np, "Loading OUI data from %s...\n", NOMADCAP_OUI_FILEPATH);

    nomadcap_loadoui(NOMADCAP_OUI_FILEPATH);
  }
#endif /* USE_LIBCSV */

  /* No file name from user, live capture */
  if (NOMADCAP_FLAG_NOT(np, FILE)) {
    np->p = pcap_open_live(np->device, NOMADCAP_SNAPLEN, NOMADCAP_PROMISC,
                           NOMADCAP_TIMEOUT, errbuf);

    /* Catch PCAP open errors */
    if (np->p == NULL) {
      NOMADCAP_STDERR(np, "pcap_open_live: %s\n", errbuf);
      nomadcap_exit(np, EXIT_FAILURE);
    }
  }

  /* Look up local network and mask */
  if (pcap_lookupnet(np->device, &np->localnet, &np->netmask, errbuf) == -1) {
    NOMADCAP_STDERR(np, "pcap_lookupnet: %s\n", errbuf);
    nomadcap_exit(np, EXIT_FAILURE);
  }

  /* Comile filter into BPF program */
  if (pcap_compile(np->p, &np->code, np->filter, 1, np->netmask) == -1) {
    NOMADCAP_STDERR(np, "pcap_compile: %s\n", pcap_geterr(np->p));
    nomadcap_exit(np, EXIT_FAILURE);
  }

  /* Set program as filter */
  if (pcap_setfilter(np->p, &np->code) == -1) {
    NOMADCAP_STDERR(np, "pcap_setfilter: %s\n", errbuf);
    nomadcap_exit(np, EXIT_FAILURE);
  }

  /* Check datalink */
  if (pcap_datalink(np->p) != DLT_EN10MB) {
    NOMADCAP_STDERR(np, "pcap_datalink: Ethernet only, sorry.");
    nomadcap_exit(np, EXIT_FAILURE);
  }

  /* Interrupt signal */
  if (nomadcap_signal(SIGINT, nomadcap_cleanup) == -1) {
    NOMADCAP_STDERR(np, "Can't catch SIGINT signal\n");
    nomadcap_exit(np, EXIT_FAILURE);
  }

  /* Duration alarm */
  if (np->duration > 0) {
    NOMADCAP_STDOUT(np, "Capturing for %d seconds\n", np->duration);

    if (nomadcap_signal(SIGALRM, nomadcap_alarm) == -1) {
      NOMADCAP_STDERR(np, "Can't catch SIGALRM signal\n");
      nomadcap_exit(np, EXIT_FAILURE);
    }

    /* Set alarm */
    alarm(np->duration);
  }

  /* Current state */
  printf("Listening on: %s\n", np->device);

  /* Verbose details.. */
  if (NOMADCAP_FLAG(np, VERB)) {
    /* Convert local network and mask to human readable strings */
    inet_ntop(AF_INET, &np->localnet, localnet_str, sizeof(localnet_str));
    inet_ntop(AF_INET, &np->netmask, netmask_str, sizeof(netmask_str));

    printf("Local network: %s\n", localnet_str);
    printf("Network mask: %s\n", netmask_str);
    printf("Filter: %s\n", NOMADCAP_FILTER);
  }

  /* Loop */
  while (loop) {
    pkt = (uint8_t *)pcap_next(np->p, &np->ph);

    /* Catch timer expiring with no data in packet buffer */
    if (pkt == NULL)
      continue;

    eth = (struct ether_header *)pkt;

    /* Cast packet to ARP header */
    arp = (struct ether_arp *)(pkt + sizeof(struct ether_header));

    /* Check if ARP header length is valid */
    if (np->ph.caplen >= sizeof(struct ether_header) + sizeof(struct arphdr)) {
      /* Check for Ethernet broadcasts */
      if (memcmp(eth->ether_dhost, NOMADCAP_BROADCAST, ETH_ALEN) == 0) {
        /* Only looking for ARP requests */
        if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REQUEST) {
          NOMADCAP_STDOUT(np, "Non ARP request, ignoring...\n");

          continue;
        }

        /* Check for ARP probe - ARP sender MAC is all zeros */
        if (memcmp(arp->arp_sha, NOMADCAP_NONE, arp->ea_hdr.ar_hln) == 0 &&
            NOMADCAP_FLAG_NOT(np, PROBES)) {
          NOMADCAP_STDOUT(np, "ARP probe, ignoring...\n");

          continue;
        }

        /* Check for ARP announcement - ARP sender and target IP match */
        if (memcmp(arp->arp_spa, arp->arp_tpa, arp->ea_hdr.ar_pln) == 0 &&
            NOMADCAP_FLAG_NOT(np, ANNOUNCE)) {
          NOMADCAP_STDOUT(np, "ARP announcement, ignoring...\n");

          continue;
        }

        /* Check if ARP request is not local */
        is_local = nomadcap_localnet(np, arp);

        if (is_local == 0 || NOMADCAP_FLAG(np, ALLNET)) {
          /* Output ARP results */
          nomadcap_output(np, arp);
        } else {
          NOMADCAP_STDOUT(np, "Local traffic, ignoring...\n");
        }
      }
    }
  }

  /* Who doesn't love statistics (verbose only) */
  if (NOMADCAP_FLAG(np, VERB)) {
    if (pcap_stats(np->p, &ps) == -1) {
      NOMADCAP_STDERR(np, "pcap_stats: %s\n", pcap_geterr(np->p));
    } else {
      NOMADCAP_STDOUT(np, "\nPackets received: %d\n", ps.ps_recv);
      NOMADCAP_STDOUT(np, "Packets dropped: %d\n", ps.ps_drop);
    }
  }

  nomadcap_exit(np, EXIT_SUCCESS);
}
