/*
 *
 * nomadcap.c [PCAP tool that aids in locating misconfigured network stacks]
 *
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* basename() */
#include <libgen.h>
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
extern int optopt;

#include "nomadcap.h"

/* Global termination control */
int loop = 1;

uint32_t nomadcap_addr2uint(nomadcap_pack_t *pack, char *addr) {
  int i;
  uint32_t result = 0;
  char *token;
  char ip_copy[INET_ADDRSTRLEN];
  
  strcpy(ip_copy, addr);

  /* Split the IP address into its four octets */
  token = strtok(ip_copy, ".");

  for (i = 0; i < 4 && token != NULL; i++) {
      result |= (atoi(token) << (24 - i * 8));
      token = strtok(NULL, ".");
  }

  return ntohl(result);
}

void nomadcap_exit(nomadcap_pack_t *np, int code) {
  if (np) {
    /* Free strings */
    if (np->device)
      free(np->device);
    if (np->filename)
      free(np->filename);

#ifdef USE_LIBCSV
    if (np->oui_data) {
      /* Loop throuh fields and free the memory */
      for (int i = 0; i < np->oui_num; i++) {
        if (np->oui_data[i].assignment)
          free(np->oui_data[i].assignment);
        if (np->oui_data[i].org_address)
          free(np->oui_data[i].org_address);
        if (np->oui_data[i].org_name)
          free(np->oui_data[i].org_name);
        if (np->oui_data[i].registry)
          free(np->oui_data[i].registry);
      }

      free(np->oui_data);
    }
#endif /* USE_LIBCSV */

    /* Close capture device */
    if (np->p)
      pcap_close(np->p);

    /* Free structure */
    free(np);
  }

  /* Exit with parameter supplied code */
  exit(code);
}

#ifdef USE_LIBCSV
nomadcap_oui_t *nomadcap_oui_lookup(nomadcap_pack_t *np,
                                    struct ether_arp *arp) {
  char oui[7], *assignment;
  int index, cindex;

  /* Convert to char[] for string compare */
  snprintf(oui, sizeof(oui), "%02X%02X%02X", arp->arp_sha[0], arp->arp_sha[1],
           arp->arp_sha[2]);

  oui[6] = '\0';

  /* Check OUI cache for a match */
  for (cindex = 0; np->oui_cache[cindex]; cindex++) {
    assignment = np->oui_cache[cindex]->assignment;

    if (strncmp(oui, assignment, 6) == 0) {
      return np->oui_cache[cindex];
    }
  }

  /* Loop through OUI entries looking for a match */
  for (index = 0; index < np->oui_num - 1; index++) {
    assignment = np->oui_data[index].assignment;

    /* Increment entry count and return the entry */
    if (strncmp(oui, assignment, 6) == 0) {
      np->oui_data[index].count++;

      /* Find first empty cache slot */
      cindex = 0;
      while(np->oui_cache[cindex] && 
        cindex < NOMADCAP_OUI_CSIZE) cindex++;

      /* Better method to check count of OUI lookkups? */

      /* Cache is full, replace random cache entry */
      if (cindex == NOMADCAP_OUI_CSIZE)
        cindex = rand() % 256;

      /* Insert found OUI entry to cache */
      np->oui_cache[cindex] = &np->oui_data[index];

      return &np->oui_data[index];
    }
  }

  return NULL;
}

void nomadcap_oui_cb1(void *field, size_t num, void *data) {
  nomadcap_pack_t *np;
  int index;

  np = (nomadcap_pack_t *)data;
  index = 0;

  /* Calculate index of OUI entry */
  if (np->oui_num > 0)
    index = np->oui_num - 1;

  /* Add more memory */
  if (np->oui_num == np->oui_max) {
    np->oui_max += NOMADCAP_OUI_ENTRIES;
    np->oui_data = (nomadcap_oui_t *)realloc(
        np->oui_data, np->oui_max * sizeof(nomadcap_oui_t));
  }

  /* Assign field data */
  switch (np->oui_index) {
  case 0:
    np->oui_data[index].registry = strdup(field);
    break;
  case 1:
    np->oui_data[index].assignment = strdup(field);
    break;
  case 2:
    np->oui_data[index].org_name = strdup(field);
    break;
  case 3:
    np->oui_data[index].org_address = strdup(field);
    break;
  default:
    break;
  }

  /* Increase OUI index for next run */
  np->oui_index++;
}

void nomadcap_oui_cb2(int num, void *data) {
  nomadcap_pack_t *np;

  np = (nomadcap_pack_t *)data;

  /* End of OUI entry row, increase number of OUIs */
  np->oui_num++;

  /* Reset field index */
  np->oui_index = 0;

  /* Set OUI entry count to zero */
  if (np->oui_num > 0) {
    np->oui_data[np->oui_num - 1].count = 0;
  }
}

u_int32_t nomadcap_oui_size(nomadcap_pack_t *np) { return np->oui_num; }

int nomadcap_oui_load(nomadcap_pack_t *np, char *path) {
  struct csv_parser cp;
  size_t nbytes;
  char buf[4096];
  FILE *fp;

  /* Open the IEEE OUI CSV file */
  fp = fopen(path, "r");

  if (fp == NULL) {
    perror("Error opening OUI data file");

    return 0;
  }

  /* Allocate memory for OUI data */
  np->oui_data = (nomadcap_oui_t *)calloc(np->oui_max, sizeof(nomadcap_oui_t));

  if (np->oui_data == NULL) {
    perror("Memory allocation error");

    return 0;
  }

  /* Initialize parser */
  csv_init(&cp, CSV_STRICT | CSV_APPEND_NULL);

  /* Read and parse OUI entries */
  /* Function _cb1 handles fields, cb2 handles row end */
  while ((nbytes = fread(buf, 1, sizeof(buf), fp)) > 0)
    if (csv_parse(&cp, buf, nbytes, nomadcap_oui_cb1, nomadcap_oui_cb2, np) !=
        nbytes)
        NOMADCAP_FAILURE(np, "Error parsing OUI data file: %s\n",
          csv_strerror(csv_error(&cp)));

  /* Clean up parser resources, close file */
  csv_fini(&cp, nomadcap_oui_cb1, nomadcap_oui_cb2, 0);

  fclose(fp);
  csv_free(&cp);

  return 1;
}
#endif /* USE_LIBCSV */

int nomadcap_islocalnet(nomadcap_pack_t *np, struct ether_arp *arp) {
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

  fprintf(stderr, "Interrupt signal\n");
}

void nomadcap_alarm(int signo) {
  loop = 0;

  fprintf(stderr, "Duration alarm\n");
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

void nomadcap_aprint(nomadcap_pack_t *np, uint8_t *addr, int size, char sep, int hex) {
  for (int i = 0; i < size; i++) {
    /* Output in hex or decimal */
    if (hex) {
      NOMADCAP_STDOUT(np, "%02x", addr[i]);
    } else {
      NOMADCAP_STDOUT(np, "%d", addr[i]);
    }

    /* Output seperator */
    if (i < size - 1)
      NOMADCAP_STDOUT(np, "%c", sep);
  }
}

void nomadcap_usage(nomadcap_pack_t *np) {
  /* Banner */
  NOMADCAP_STDOUT(np, "%s v%s [%s]\n\n", np->pname, NOMADCAP_VERSION,
                  NOMADCAP_BANNER);

  /* Command line options */
  NOMADCAP_STDOUT(
      np, "Usage: %s [-i INTF] [-n NETWORK -m NETMASK] [-f FILE.PCAP] [-d SECONDS] [-",
      np->pname);
#ifdef USE_LIBCSV
  NOMADCAP_STDOUT(np, "O");
#endif /* USE_LIBCSV */
  NOMADCAP_STDOUT(np, "Apa1LvV]\n\n");

  NOMADCAP_STDOUT(np, "\t-i INTF\t\tCapture on specific interface\n");
  NOMADCAP_STDOUT(np, "\t-n NETWORK\tCapture network (e.g. 192.0.2.0)\n");
  NOMADCAP_STDOUT(np, "\t-m NETMASK\tCapture netmask (e.g. 255.255.255.0)\n");
  NOMADCAP_STDOUT(
      np, "\t-f FILE.PCAP\tOffline capture using FILE.PCAP\n");
  NOMADCAP_STDOUT(np, "\t-d SECONDS\tDuration of capture (default: %d)\n", NOMADCAP_DURATION);

#ifdef USE_LIBCSV
  NOMADCAP_STDOUT(np, "\t-O\t\tMAC OUI to organization\n");
#endif /* USE_LIBCSV */

  NOMADCAP_STDOUT(np, "\t-A\t\tAll networks (ARP request monitor)\n");
  NOMADCAP_STDOUT(np, "\t-p\t\tProcess ARP probes\n");
  NOMADCAP_STDOUT(np, "\t-a\t\tProcess ARP announcements\n");
  NOMADCAP_STDOUT(np, "\t-1\t\tExit after single match\n");
  NOMADCAP_STDOUT(np, "\t-L\t\tList available interfaces\n");
  NOMADCAP_STDOUT(np, "\t-v\t\tVerbose mode\n");
  NOMADCAP_STDOUT(np, "\t-V\t\tVersion\n");

  NOMADCAP_STDOUT(np, "\nAuthor: %s\n", NOMADCAP_AUTHOR);
}

/* Format: <Sender IP> [<Sender MAC>] is looking for <Target IP> */
void nomadcap_output(nomadcap_pack_t *np, struct ether_arp *arp) {
#ifdef USE_LIBCSV
  nomadcap_oui_t *oui_entry;
#endif /* USE_LIBCSV */

  /* Sender IP */
  nomadcap_aprint(np, arp->arp_spa, 4, '.', 0);

  /* Sender MAC */
  NOMADCAP_STDOUT(np, " [");
  nomadcap_aprint(np, arp->arp_sha, ETH_ALEN, ':', 1);

#ifdef USE_LIBCSV
  /* Output OUI org. details */
  if (NOMADCAP_FLAG(np, OUI)) {
    oui_entry = nomadcap_oui_lookup(np, arp);

    if (oui_entry)
      NOMADCAP_STDOUT(np, " - %s", oui_entry->org_name);
  }
#endif /* USE_LIBCSV */

  NOMADCAP_STDOUT(np, "] is looking for ");

  /* Target IP */
  nomadcap_aprint(np, arp->arp_tpa, 4, '.', 0);

  NOMADCAP_STDOUT(np, "\n");
}

nomadcap_pack_t *nomadcap_init(char *pname) {
#ifdef USE_LIBCSV
  int i;
#endif /* USE_LIBCSV */
  nomadcap_pack_t *np;

  np = (nomadcap_pack_t *)malloc(sizeof(nomadcap_pack_t));

  if (np) {
    /* Set some sane defaults */
    np->device = NULL;
    np->filename = NULL;
    np->p = NULL;
    np->filter = NOMADCAP_FILTER;
    np->flags = NOMADCAP_FLAGS_NONE;

    /* Capture forever by default */
    np->duration = 0;

#ifdef USE_LIBCSV
    /* Initialize OUI data and state variables */
    np->oui_data = NULL;

    /* Start with a clear cache */
    for (i = 0; i < NOMADCAP_OUI_CSIZE; i++)
      np->oui_cache[i] = NULL;
    
    np->oui_num = 0;
    np->oui_index = 0;
    np->oui_max = NOMADCAP_OUI_ENTRIES;
#endif /* USE_LIBCSV */

    /* Save program name */
    np->pname = basename(pname);

    return np;
  }

  return NULL;
}

int nomadcap_interesting(nomadcap_pack_t *np, struct ether_header *eth,
                         struct ether_arp *arp) {
  if (np->ph.caplen >= sizeof(struct ether_header) + sizeof(struct arphdr)) {
    if (memcmp(eth->ether_dhost, NOMADCAP_BROADCAST, ETH_ALEN) == 0) {
      /* Only looking for ARP requests */
      if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REQUEST) {
        NOMADCAP_STDOUT_V(np, "Non ARP request, ignoring...\n");

        return 0;
      }

      /* Check for ARP probe - ARP sender MAC is all zeros */
      if (memcmp(arp->arp_sha, NOMADCAP_NONE, arp->ea_hdr.ar_hln) == 0 &&
          NOMADCAP_FLAG_NOT(np, PROBES)) {
        NOMADCAP_STDOUT_V(np, "ARP probe, ignoring...\n");

        return 0;
      }

      /* Check for ARP announcement - ARP sender and target IP match */
      if (memcmp(arp->arp_spa, arp->arp_tpa, arp->ea_hdr.ar_pln) == 0 &&
          NOMADCAP_FLAG_NOT(np, ANNOUNCE)) {
        NOMADCAP_STDOUT_V(np, "ARP announcement, ignoring...\n");

        return 0;
      }

      /* Interesting traffic */
      return 1;
    }
  }

  /* Boring traffic */
  return 0;
}

void nomadcap_printdevs(nomadcap_pack_t *np, char *errbuf) {
  pcap_if_t *devs, *dev;
  bpf_u_int32 net, mask;
  char net_s[INET_ADDRSTRLEN];
  char mask_s[INET_ADDRSTRLEN];

  /* Find all available network interfaces */
  if (pcap_findalldevs(&devs, errbuf) == -1)
    NOMADCAP_FAILURE(np, "pcap_findalldevs: %s\n", errbuf);

  /* No interfaces, print an error message and exit */
  if (devs == NULL)
    NOMADCAP_FAILURE(np, "No interfaces found\n");

  /* Loop through devices */
  for (dev = &devs[0]; dev != NULL; dev = dev->next) {
    /* Look up device network and mask */
    if (pcap_lookupnet(dev->name, &net, &mask, errbuf) == -1)
      NOMADCAP_FAILURE(np, "pcap_lookupnet: %s\n", errbuf);

    /* Output device if network settings found */
    if (net != 0) {
      /* Convert network and mask to human readable strings */
      inet_ntop(AF_INET, &net, net_s, sizeof(net_s));
      inet_ntop(AF_INET, &mask, mask_s, sizeof(mask_s));

      /* Output device details */
      NOMADCAP_STDOUT(np, "%s\t%s\t%s\n", dev->name, net_s, mask_s);
    }
  }

  /* Free the list of interfaces */
  pcap_freealldevs(devs);
}

int main(int argc, char *argv[]) {
  nomadcap_pack_t *np;
  struct pcap_stat ps;
  struct ether_header *eth;
  struct ether_arp *arp;
  char errbuf[PCAP_ERRBUF_SIZE];
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
#ifdef USE_LIBCSV
    case 'O': /* OUI look up */
      np->flags |= NOMADCAP_FLAGS_OUI;
      break;
#endif /* USE_LIBCSV */
    case 'A': /* All networks (request monitor) */
      np->flags |= NOMADCAP_FLAGS_ALLNET;
      break;
    case 'p': /* Process ARP probes */
      np->flags |= NOMADCAP_FLAGS_PROBES;
      break;
    case 'a': /* Process ARP announcements */
      np->flags |= NOMADCAP_FLAGS_ANNOUNCE;
      break;
    case 'i': /* Capture interface/device */
      np->device = strdup(optarg);
      break;
    case 'n': /* Capture network */
      np->flags |= NOMADCAP_FLAGS_NETWORK;
      np->localnet = nomadcap_addr2uint(np, optarg);
      break;
    case 'm': /* Capture netmask */
      np->flags |= NOMADCAP_FLAGS_NETMASK;
      np->netmask = nomadcap_addr2uint(np, optarg);
      break;
    case 'f': /* Offline capture file */
      np->flags |= NOMADCAP_FLAGS_FILE;
      np->filename = strdup(optarg);
      break;
    case 'd': /* Capture duration */
      /* User supplied duration or default */
      np->duration = optarg ? atoi(optarg) : NOMADCAP_DURATION;
      break;
    case 'v': /* Verbose */
      np->flags |= NOMADCAP_FLAGS_VERBOSE;
      break;
    case '1': /* Single match */
      np->flags |= NOMADCAP_FLAGS_ONE;
      break;
    case 'L': /* List interfaces */
      nomadcap_printdevs(np, errbuf);
      NOMADCAP_SUCCESS(np);
    case 'V': /* Version */
      NOMADCAP_STDOUT(np, "%s\n", NOMADCAP_VERSION);
      NOMADCAP_SUCCESS(np);
    case 'h': /* Help screen */
      nomadcap_usage(np);
      NOMADCAP_SUCCESS(np);
    default: /* '?' */
      NOMADCAP_WARNING(np, "Unknown switch -%c, check -h.\n", optopt);
    }
  }

  /* Warn if using file capture with device network and mask */
  if (NOMADCAP_FLAG(np, FILE) &&
    NOMADCAP_FLAG_NOT(np, NETWORK))
      NOMADCAP_WARNING(np, "WARNING: Using -f (file) capture without -n (network) switch\n");

  /* Exit with message to use netmask switch */
  if (NOMADCAP_FLAG(np, NETWORK) && 
    NOMADCAP_FLAG_NOT(np, NETMASK))
      NOMADCAP_FAILURE(np, "Use -m (netmask) with -n (network) switch\n");

  /* Leave it to libpcap to find an interface */
  if (np->device == NULL)
    nomadcap_finddev(np, errbuf);

  NOMADCAP_STDOUT_V(np, "Flags: 0x%08x\n", np->flags);

  /* Load IEEE OUI data */
#ifdef USE_LIBCSV
  if (NOMADCAP_FLAG(np, OUI)) {
    NOMADCAP_STDOUT_V(np, "Loading OUI data from %s...\n",
                      NOMADCAP_OUI_FILEPATH);

    nomadcap_oui_load(np, NOMADCAP_OUI_FILEPATH);

    NOMADCAP_STDOUT_V(np, "Loaded %d OUIs\n", nomadcap_oui_size(np));
  }
#endif /* USE_LIBCSV */

  /* Open device/file, set filter, check datalink, and
    .lookup network and mask */
  nomadcap_pcap_setup(np, errbuf);

  /* Setup signal handlers */
  nomadcap_signals(np);

  /* Current state */
  NOMADCAP_STDOUT(np, "Listening on: %s\n", np->device);

  /* Network details (verbose only)... */
  if (NOMADCAP_FLAG(np, VERBOSE))
    nomadcap_netprint(np);

  /* Loop */
  while (loop) {
    pkt = (uint8_t *)pcap_next(np->p, &np->ph);

    /* Bail if we have no data and in offline mode */
    if (pkt == NULL && NOMADCAP_FLAG(np, FILE)) {
      NOMADCAP_STDOUT_V(np, "Reached end of capture file: %s\n", np->filename);

      /* Prevents looping forever */
      loop = 0;
    }

    /* Catch timer expiring with no data in packet buffer */
    if (pkt == NULL)
      continue;

    /* Cast packet to Ethernet header */
    eth = (struct ether_header *)pkt;

    /* Cast packet to ARP header */
    arp = (struct ether_arp *)(pkt + sizeof(struct ether_header));

    /* Check for interesting traffic */
    if (nomadcap_interesting(np, eth, arp)) {
      /* Check if ARP request is not local */
      is_local = nomadcap_islocalnet(np, arp);

      /* Output results if not local or all networks flag set */
      if (is_local == 0 || NOMADCAP_FLAG(np, ALLNET)) {
        nomadcap_output(np, arp);

        /* Terminate loop if only looking for one match */
        if (NOMADCAP_FLAG(np, ONE)) loop = 0;
      } else {
        NOMADCAP_STDOUT_V(np, "Local traffic, ignoring...\n");
      }
    }
  }

  /* Who doesn't love statistics (verbose only) */
  if (NOMADCAP_FLAG(np, VERBOSE) && NOMADCAP_FLAG_NOT(np, FILE)) {
    if (pcap_stats(np->p, &ps) == -1) {
      NOMADCAP_STDERR(np, "pcap_stats: %s\n", pcap_geterr(np->p));
    } else {
      NOMADCAP_STDOUT(np, "\nPackets received: %d\n", ps.ps_recv);
      NOMADCAP_STDOUT(np, "Packets dropped: %d\n", ps.ps_drop);
    }
  }

  nomadcap_exit(np, EXIT_SUCCESS);
}

void nomadcap_finddev(nomadcap_pack_t *np, char *errbuf) {
  pcap_if_t *devs;

  NOMADCAP_STDOUT_V(np, "Looking for interface...\n");

  /* Find all available network interfaces */
  if (pcap_findalldevs(&devs, errbuf) == -1)
    NOMADCAP_FAILURE(np, "pcap_findalldevs: %s\n", errbuf);

  /* No interfaces, print an error message and exit */
  if (devs == NULL)
    NOMADCAP_FAILURE(np, "No interfaces found\n");

  /* Copy device name of first found device */
  np->device = strdup(devs[0].name);

  NOMADCAP_STDOUT_V(np, "Found interface: %s\n", np->device);

  /* Free the list of interfaces */
  pcap_freealldevs(devs);
}

void nomadcap_netprint(nomadcap_pack_t *np) {
  char localnet_s[INET_ADDRSTRLEN];
  char netmask_s[INET_ADDRSTRLEN];

  /* Convert local network and mask to human readable strings */
  inet_ntop(AF_INET, &np->localnet, localnet_s, sizeof(localnet_s));
  inet_ntop(AF_INET, &np->netmask, netmask_s, sizeof(netmask_s));

  NOMADCAP_STDOUT(np, "Local network: %s\n", localnet_s);
  NOMADCAP_STDOUT(np, "Network mask: %s\n", netmask_s);
}

void nomadcap_pcap_setup(nomadcap_pack_t *np, char *errbuf) {
  /* No file name from user, live capture */
  if (NOMADCAP_FLAG_NOT(np, FILE)) {
    np->p = pcap_open_live(np->device, NOMADCAP_SNAPLEN, NOMADCAP_PROMISC,
                           NOMADCAP_TIMEOUT, errbuf);

    /* Catch open errors */
    if (np->p == NULL)
      NOMADCAP_FAILURE(np, "pcap_open_live: %s\n", errbuf);
  } else {
    /* Offline capture */
    NOMADCAP_STDOUT_V(np, "Loading capture file: %s\n", np->filename);

    /* Open file */
    np->p = pcap_open_offline(np->filename, errbuf);

    /* Catch open errors */
    if (np->p == NULL)
      NOMADCAP_FAILURE(np, "pcap_open_offline: %s\n", errbuf);
  }

  /* Look up local network and mask, if not provided by user on command line */
  if (NOMADCAP_FLAG_NOT(np, NETWORK) && 
    pcap_lookupnet(np->device, &np->localnet, &np->netmask, errbuf) == -1)
      NOMADCAP_FAILURE(np, "pcap_lookupnet: %s\n", errbuf);

  /* Compile filter into BPF program */
  if (pcap_compile(np->p, &np->code, np->filter, 1, np->netmask) == -1)
    NOMADCAP_FAILURE(np, "pcap_compile: %s\n", pcap_geterr(np->p));

  /* Set program as filter */
  if (pcap_setfilter(np->p, &np->code) == -1)
    NOMADCAP_FAILURE(np, "pcap_setfilter: %s\n", errbuf);

  /* Check datalink */
  if (pcap_datalink(np->p) != DLT_EN10MB)
    NOMADCAP_FAILURE(np, "pcap_datalink: Ethernet only, sorry.");
}

void nomadcap_signals(nomadcap_pack_t *np) {
  /* Interrupt signal */
  if (nomadcap_signal(SIGINT, nomadcap_cleanup) == -1)
    NOMADCAP_FAILURE(np, "Can't catch SIGINT signal\n");

  /* Duration alarm */
  if (np->duration > 0) {
    NOMADCAP_STDOUT_V(np, "Capturing for %d seconds\n", np->duration);

    if (nomadcap_signal(SIGALRM, nomadcap_alarm) == -1)
      NOMADCAP_FAILURE(np, "Can't catch SIGALRM signal\n");

    /* Set alarm */
    alarm(np->duration);
  }
}
