/*
 *
 * nomadcap6.c [PCAP tool that aids in locating misconfigured v6 network stacks]
 *
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <locale.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <ifaddrs.h>

/* basename() */
#include <libgen.h>
#include <unistd.h>

/* PCAP */
#include <pcap.h>

/* Ethernet and IPv6 */
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>

#ifdef USE_LIBCSV
#include <csv.h>
#endif /* USE_LIBCSV */

#ifdef USE_LIBJANSSON
#include <jansson.h>
#endif /* USE_LIBJANSSON */

/* getopt friends */
extern char *optarg;
extern int optopt;

#include "nomadcap6.h"
#include "syslog.h"

void nomadcap6_exit(nomadcap6_pack_t *np, int code) {
  if (np) {
    if (np->device)
      free(np->device);
    if (np->filename)
      free(np->filename);
    if (np->binary)
      free(np->binary);
    if (np->prefixes)
      free(np->prefixes);

#ifdef USE_LIBCSV
    /* Free IEEE OUI data */
    nomadcap_oui_free(&np->oui);
#endif /* USE_LIBCSV */

#ifdef USE_LIBJANSSON
    if (np->json)
      json_decref(np->json);
#endif /* USE_LIBJANSSON*/

    if (np->p)
      pcap_close(np->p);

    /* Close syslog */
    if (NOMADCAP6_FLAG(np, SYSLOG))
      nomadcap_closelog();

    free(np);
  }

  exit(code);
}

int nomadcap6_prefixlen(struct sockaddr_in6 *nm6) {
  uint8_t *p = (uint8_t *)&nm6->sin6_addr;
  int prefixlen = 0;

  for (int i = 0; i < 16; i++) {
    uint8_t c = p[i];

    while (c) {
      prefixlen += (c & 0x80) ? 1 : 0;
      c <<= 1;
    }
  }

  return prefixlen;
}

void nomadcap6_add_prefix(nomadcap6_pack_t *np, struct in6_addr *addr, int prefixlen) {
  if (np->prefixes == NULL) {
    np->prefixes = (nomadcap6_prefix_t *)calloc(np->prefix_max,
        sizeof(nomadcap6_prefix_t));

    if (np->prefixes == NULL)
      NOMADCAP6_FAILURE(np, "nomadcap6_add_prefix: alloc failure\n");
  }

  if (np->prefix_num == np->prefix_max) {
    np->prefix_max += NOMADCAP6_PREFIX_ENTRIES;
    np->prefixes = (nomadcap6_prefix_t *)realloc(np->prefixes,
        np->prefix_max * sizeof(nomadcap6_prefix_t));

    if (np->prefixes == NULL)
      NOMADCAP6_FAILURE(np, "nomadcap6_add_prefix: realloc failure\n");
  }

  /* Apply mask to get network prefix */
  memcpy(&np->prefixes[np->prefix_num].prefix, addr, sizeof(struct in6_addr));

  int nbytes = prefixlen / 8;
  int rbits = prefixlen % 8;
  uint8_t *p = (uint8_t *)&np->prefixes[np->prefix_num].prefix;

  if (rbits)
    p[nbytes] &= (0xff << (8 - rbits));

  for (int i = nbytes + (rbits ? 1 : 0); i < 16; i++)
    p[i] = 0;

  np->prefixes[np->prefix_num].prefixlen = prefixlen;
  np->prefix_num++;

  np->flags |= NOMADCAP6_FLAGS_NETWORK;
}

void nomadcap6_get_prefix(nomadcap6_pack_t *np) {
  struct ifaddrs *ifaddr, *ifa;
  struct sockaddr_in6 *sin6, *nm6;
  int prefixlen;

  if (getifaddrs(&ifaddr) == -1)
    return;

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET6)
      continue;
    if (strcmp(ifa->ifa_name, np->device) != 0)
      continue;

    sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
    prefixlen = 0;

    if (ifa->ifa_netmask) {
      nm6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
      prefixlen = nomadcap6_prefixlen(nm6);
    }

    nomadcap6_add_prefix(np, &sin6->sin6_addr, prefixlen);
  }

  freeifaddrs(ifaddr);
}

int nomadcap6_islocalnet(nomadcap6_pack_t *np, struct in6_addr *addr) {
  for (uint32_t i = 0; i < np->prefix_num; i++) {
    int nbytes = np->prefixes[i].prefixlen / 8;
    int rbits = np->prefixes[i].prefixlen % 8;
    int match = 1;

    if (memcmp(addr, &np->prefixes[i].prefix, nbytes) != 0)
      match = 0;

    if (match && rbits) {
      uint8_t mask = 0xff << (8 - rbits);

      if ((((uint8_t *)addr)[nbytes] & mask) !=
          (((uint8_t *)&np->prefixes[i].prefix)[nbytes] & mask))
        match = 0;
    }

    if (match)
      return 1;
  }

  return 0;
}

void nomadcap6_setup(nomadcap6_pack_t *np, char *errbuf) {
  /* Set the locale to the user default */
  setlocale(LC_NUMERIC, "");

  if (NOMADCAP6_FLAG(np, FILE))
    np->duration = 0;

#ifdef USE_LIBJANSSON
  if (NOMADCAP6_FLAG(np, JSON)) {
    np->json = json_object();

    NOMADCAP6_JSON_PACK(np, "results", json_array());
  }
#endif /* USE_LIBJANSSON */

  if (NOMADCAP6_FLAG(np, FILE) &&
    NOMADCAP6_FLAG_NOT(np, NETWORK))
      NOMADCAP6_WARNING(np, "WARNING: Using -f (file) capture without -n (network) switch\n");

  if (np->device == NULL)
    nomadcap6_finddev(np, errbuf);

  /* Auto-detect local prefix if not specified and not reading from file */
  if (NOMADCAP6_FLAG_NOT(np, NETWORK) && NOMADCAP6_FLAG_NOT(np, FILE))
    nomadcap6_get_prefix(np);

  NOMADCAP6_STDOUT_V(np, "Flags: 0x%08x\n", np->flags);
  NOMADCAP6_SYSLOG_V(np, LOG_INFO, "Flags: 0x%08x\n", np->flags);

  if (np->binary) {
    NOMADCAP6_STDOUT_V(np, "Binary: %s\n", np->binary);
    NOMADCAP6_SYSLOG_V(np, LOG_INFO, "Binary: %s\n", np->binary);
  }

#ifdef USE_LIBJANSSON
  if (NOMADCAP6_FLAG(np, JSON))
    NOMADCAP6_JSON_PACK_V(np, "flags", json_integer(np->flags));
#endif /* USE_LIBJANSSON */

#ifdef USE_LIBCSV
  if (NOMADCAP6_FLAG(np, OUI)) {
    char oui_err[256];
    int rc;

    NOMADCAP6_STDOUT_V(np, "Loading OUI data from %s...\n",
                      NOMADCAP_OUI_FILEPATH);
    NOMADCAP6_SYSLOG_V(np, LOG_INFO, "Loading OUI data from %s...\n",
                      NOMADCAP_OUI_FILEPATH);

    rc = nomadcap_oui_load(&np->oui, NOMADCAP_OUI_FILEPATH, oui_err,
                           sizeof(oui_err));

    /* Parse or allocation error */
    if (rc < 0) {
      NOMADCAP6_SYSLOG(np, LOG_ERR, "%s\n", oui_err);
      NOMADCAP6_FAILURE(np, "%s\n", oui_err);
    }

    /* OUI file not available, continue without lookups */
    if (rc == 0)
      NOMADCAP6_WARNING(np, "%s\n", oui_err);

    NOMADCAP6_STDOUT_V(np, "Loaded %'d OUIs\n", nomadcap_oui_size(&np->oui));
    NOMADCAP6_SYSLOG_V(np, LOG_INFO, "Loaded %'d OUIs\n", nomadcap_oui_size(&np->oui));

#ifdef USE_LIBJANSSON
    if (NOMADCAP6_FLAG(np, JSON)) {
      NOMADCAP6_JSON_PACK_V(np, "oui_file", json_string(NOMADCAP_OUI_FILEPATH));
      NOMADCAP6_JSON_PACK_V(np, "ouis", json_integer(nomadcap_oui_size(&np->oui)));
    }
#endif /* USE_LIBJANSSON */
  }
#endif /* USE_LIBCSV */

  nomadcap6_pcap_setup(np, errbuf);
  nomadcap6_signals(np);
}

#ifdef USE_LIBJANSSON
void nomadcap6_json_print(nomadcap6_pack_t *np) {
  char *json_string = json_dumps(np->json, JSON_INDENT(2));

  if (json_string) {
    printf("%s", json_string);

    free(json_string);
  }
}
#endif /* USE_LIBJANSSON */

void nomadcap6_usage(nomadcap6_pack_t *np) {
  /* Banner */
  NOMADCAP6_STDOUT(np, "%s v%s [%s]\n\n", np->pname, NOMADCAP6_VERSION,
                  NOMADCAP6_BANNER);

  /* Command line options */
  NOMADCAP6_STDOUT(
      np, "Usage: %s [-i INTF] [-n PREFIX/LENGTH] [--vlan X,Y,Z]"
	  " [-f FILE.PCAP] [-d SECONDS] [-x PATH] [-",
      np->pname);
#ifdef USE_LIBCSV
  NOMADCAP6_STDOUT(np, "O");
#endif /* USE_LIBCSV */

#ifdef USE_LIBJANSSON
  NOMADCAP6_STDOUT(np, "j");
#endif /* USE_LIBJANSSON */

  NOMADCAP6_STDOUT(np, "Aa1stuLvV]\n\n");

  NOMADCAP6_STDOUT(np, "Options:\n");
  NOMADCAP6_HELP_OPT(np, "-i, --interface=INTF", "Capture on specific interface");
  NOMADCAP6_HELP_OPT(np, "-n, --network=PREFIX/LEN", "Capture network (e.g. fe80::/10)");
  NOMADCAP6_HELP_OPT(np, "--vlan X,Y,Z", "Specific VLANs to monitor");
  NOMADCAP6_HELP_OPT(np, "-f, --file=FILE.PCAP", "Offline capture using FILE.PCAP");
  NOMADCAP6_HELP_OPT(np, "-d, --duration=SECONDS", "Duration of capture (default: " XSTR(NOMADCAP6_DURATION) ", forever: 0)");

#ifdef USE_LIBCSV
  NOMADCAP6_HELP_OPT(np, "-O, --oui", "MAC OUI to organization");
#endif /* USE_LIBCSV */

  NOMADCAP6_HELP_OPT(np, "-A, --all", "All networks");
  NOMADCAP6_HELP_OPT(np, "-a, --announce", "Process unsolicited neighbor advertisements");
  NOMADCAP6_HELP_OPT(np, "-1, --once", "Exit after single match");
  NOMADCAP6_HELP_OPT(np, "-x, --exec=PATH", "Execute on detection");
  NOMADCAP6_HELP_OPT(np, "-s, --syslog", "Send to syslog");
  NOMADCAP6_HELP_OPT(np, "-t, --timestamp", "ISO 8601 timestamps");
  NOMADCAP6_HELP_OPT(np, "-u, --utc", "Show timestamps in UTC");
  NOMADCAP6_HELP_OPT(np, "-L, --list", "List available interfaces");

#ifdef USE_LIBJANSSON
  NOMADCAP6_HELP_OPT(np, "-j, --json", "JSON output");
#endif /* USE_LIBJANSSON */

  NOMADCAP6_HELP_OPT(np, "-v, --verbose", "Verbose mode");
  NOMADCAP6_HELP_OPT(np, "-V, --version", "Version");

  NOMADCAP6_STDOUT(np, "\nAuthor: %s\n", NOMADCAP6_AUTHOR);
}

void nomadcap6_output(nomadcap6_pack_t *np, struct ether_header *eth,
                      struct ip6_hdr *ip, struct icmp6_hdr *icmp) {
  char src_ip[INET6_ADDRSTRLEN], tgt_ip[INET6_ADDRSTRLEN];
  char src_ha[NOMADCAP6_ETH_ADDRSTRLEN];
  char ts[NOMADCAP6_TSLEN];
  char output[512];
  size_t w;
  struct nd_neighbor_solicit *ns;

#ifdef USE_LIBCSV
  nomadcap_oui_t *oui_entry;
#endif /* USE_LIBCSV */

#ifdef USE_LIBJANSSON
  json_t *results, *result;
#endif /* USE_LIBJANSSON */

  memset(src_ip, 0, sizeof(src_ip));
  memset(src_ha, 0, sizeof(src_ha));
  memset(tgt_ip, 0, sizeof(tgt_ip));
  memset(ts, 0, sizeof(ts));
  memset(output, 0, sizeof(output));
  w = 0;

  /* Extract source IPv6 address */
  inet_ntop(AF_INET6, &ip->ip6_src, src_ip, sizeof(src_ip));

  /* Extract source MAC from Ethernet header */
  snprintf(src_ha, sizeof(src_ha), "%02x:%02x:%02x:%02x:%02x:%02x",
    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
    eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

  /* Extract target address from ND message (same offset for NS and NA) */
  ns = (struct nd_neighbor_solicit *)icmp;
  inet_ntop(AF_INET6, &ns->nd_ns_target, tgt_ip, sizeof(tgt_ip));

  /* Timestamp */
  nomadcap_iso8601(np->ts_func, ts, sizeof(ts));

  if (NOMADCAP6_FLAG(np, TS))
    w = snprintf(output, sizeof(output), "%s - ", ts);

  /* Final output: [Timestamp] <Sender IP> [<Sender MAC> - Org] is looking for <Target IP> */
  w += snprintf(output + w, sizeof(output) - w, "%s [%s", src_ip, src_ha);

#ifdef USE_LIBCSV
  /* Output OUI org. details */
  if (NOMADCAP6_FLAG(np, OUI)) {
    oui_entry = nomadcap_oui_lookup(&np->oui, eth->ether_shost);

    if (oui_entry)
      w += snprintf(output + w, sizeof(output) - w, " - %s", oui_entry->org_name);
  }
#endif /* USE_LIBCSV */

  snprintf(output + w, sizeof(output) - w, "] is looking for %s\n", tgt_ip);

  /* Output target IP */
  NOMADCAP6_STDOUT(np, "%s", output);
  NOMADCAP6_SYSLOG(np, LOG_INFO, "%s", output);

#ifdef USE_LIBJANSSON
  if (NOMADCAP6_FLAG(np, JSON)) {
    results = json_object_get(np->json, "results");
    result = json_object();

    if (results == NULL)
      results = json_array();

    json_object_set_new(result, "src_ip", json_string(src_ip));
    json_object_set_new(result, "src_ha", json_string(src_ha));
    json_object_set_new(result, "tgt_ip", json_string(tgt_ip));

    if (NOMADCAP6_FLAG(np, TS))
      json_object_set_new(result, "ts", json_string(ts));

#ifdef USE_LIBCSV
    if (NOMADCAP6_FLAG(np, OUI) && oui_entry)
        json_object_set_new(result, "org", json_string(oui_entry->org_name));
#endif /* USE_LIBCSV */

    json_array_append_new(results, result);
    json_incref(results);

    NOMADCAP6_JSON_PACK(np, "results", results);
  }
#endif /* USE_LIBJANSSON */
}

nomadcap6_pack_t *nomadcap6_init(char *pname) {
  nomadcap6_pack_t *np;

  np = (nomadcap6_pack_t *)malloc(sizeof(nomadcap6_pack_t));

  if (np) {
    /* Set some sane defaults */
    np->device = NULL;
    np->filename = NULL;
    np->p = NULL;
    np->filter = NOMADCAP6_FILTER;
    np->flags = NOMADCAP6_FLAGS_NONE;

    /* Default to duration capture, 0 to capture forever */
    np->duration = NOMADCAP6_DURATION;

#ifdef USE_LIBCSV
    /* Initialize OUI data, state, and cache */
    memset(&np->oui, 0, sizeof(np->oui));
#endif /* USE_LIBCSV */

#ifdef USE_LIBJANSSON
    np->json = NULL;
#endif /* USE_LIBJANSSON */

    /* Save program name */
    np->pname = basename(pname);
    np->ts_func = localtime;
    np->binary = NULL;

    np->prefixes = NULL;
    np->prefix_num = 0;
    np->prefix_max = NOMADCAP6_PREFIX_ENTRIES;

    return np;
  }

  return NULL;
}

int nomadcap6_interesting(nomadcap6_pack_t *np, struct ether_header *eth,
                         struct icmp6_hdr *icmp,
			 const struct pcap_pkthdr *ph) {
  /* Offset of the ND message within the captured packet */
  size_t nd_off = (const u_char *)icmp - (const u_char *)eth;

  /* Check for specific VLAN traffic */
  if (np->vlan_cnt && !nomadcap_vlan_match(eth, np->vlans, np->vlan_cnt)) {
    /* Not interested in this VLAN traffic */
    return 0;
  }

  /* Check for ICMPv6 Neighbor Discovery messages */
  if (icmp->icmp6_type != ND_NEIGHBOR_SOLICIT &&
		  icmp->icmp6_type != ND_NEIGHBOR_ADVERT) {
    NOMADCAP6_STDOUT_V(np, "Non-NDP ICMPv6 message, ignoring...\n");
    NOMADCAP6_SYSLOG_V(np, LOG_INFO, "Non-NDP ICMPv6 message, ignoring...\n");

    return 0;
  }

  /* ND target address must be captured (same layout for NS and NA) */
  if (ph->caplen < nd_off + sizeof(struct nd_neighbor_solicit))
    return 0;

  /* Handle Neighbor Solicitation (equivalent to ARP request) */
  if (icmp->icmp6_type == ND_NEIGHBOR_SOLICIT) {
    /* NS should be sent to solicited-node multicast */
    if ((eth->ether_dhost[0] & 0x01) == 0) {
      NOMADCAP6_STDOUT_V(np, "Unicast NS, ignoring...\n");
      NOMADCAP6_SYSLOG_V(np, LOG_INFO, "Unicast NS, ignoring...\n");
      return 0;
    }

    return 1;
  }

  /* Handle Neighbor Advertisement (equivalent to ARP reply) */
  struct nd_neighbor_advert *na = (struct nd_neighbor_advert *)icmp;

  /* Check for unsolicited advertisement (announcement) */
  if ((na->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED) == 0 &&
      NOMADCAP6_FLAG_NOT(np, ANNOUNCE)) {
    NOMADCAP6_STDOUT_V(np, "Unsolicited Neighbor Advertisement (announcement), ignoring...\n");
    NOMADCAP6_SYSLOG_V(np, LOG_INFO, "Unsolicited Neighbor Advertisement (announcement), ignoring...\n");

    return 0;
  }

  /* Solicited NA, or unsolicited with -a */
  return 1;
}

void nomadcap6_printdevs(nomadcap6_pack_t *np, char *errbuf) {
  struct sockaddr_in6 *sin6, *nm6;
  struct ifaddrs *ifaddr, *ifa;
  char addrbuf[INET6_ADDRSTRLEN];
  int prefixlen;

  if (getifaddrs(&ifaddr) == -1)
    NOMADCAP6_FAILURE(np, "getifaddrs: %s\n", strerror(errno));

  /* Enumerate interfaces for IPv6 addresses, output details when found */
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;

    if (ifa->ifa_addr->sa_family == AF_INET6) {
      sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
      inet_ntop(AF_INET6, &sin6->sin6_addr, addrbuf, sizeof(addrbuf));

      /* Find prefix length */
      prefixlen = 0;

      if (ifa->ifa_netmask) {
		nm6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
		prefixlen = nomadcap6_prefixlen(nm6);
      }

      NOMADCAP6_STDOUT(np, "%s\t%s/%d\n", ifa->ifa_name, addrbuf, prefixlen);
    }
  }

  freeifaddrs(ifaddr);
}

void nomadcap6_pcap_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt) {
  struct ether_header *eth;
  nomadcap6_pack_t *np = (nomadcap6_pack_t *)user;
  struct ip6_hdr *ip;
  struct icmp6_hdr *icmp;
  size_t offset = sizeof(struct ether_header);
  int is_local;

  eth = (struct ether_header *)pkt;

  /* 802.1Q tag sits between the Ethernet header and the IPv6 header */
  if (h->caplen >= sizeof(struct ether_header) &&
      ntohs(eth->ether_type) == ETHERTYPE_VLAN)
    offset += NOMADCAP_VLAN_HDRLEN;

  /* IPv6 and ICMPv6 headers must be captured */
  if (h->caplen < offset + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)) {
    if (!nomadcap_loop) pcap_breakloop(np->p);

    return;
  }

  ip = (struct ip6_hdr *)(pkt + offset);

  /* Verify next header is ICMPv6 (extension headers not supported) */
  if (ip->ip6_nxt != IPPROTO_ICMPV6) {
    NOMADCAP6_STDOUT_V(np, "IPv6 next header %d, ignoring...\n", ip->ip6_nxt);
  } else {
    icmp = (struct icmp6_hdr *)(pkt + offset + sizeof(struct ip6_hdr));

    /* Check for interesting traffic */
    if (nomadcap6_interesting(np, eth, icmp, h)) {
      is_local = 0;

      /* Check if target is on the local network */
      if (NOMADCAP6_FLAG(np, NETWORK)) {
        struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *)icmp;
        struct in6_addr target;

        memcpy(&target, &ns->nd_ns_target, sizeof(target));
        is_local = nomadcap6_islocalnet(np, &target);
      }

      /* Output results if not local or all networks flag set */
      if (is_local == 0 || NOMADCAP6_FLAG(np, ALLNET)) {
        nomadcap6_output(np, eth, ip, icmp);

        /* Execute binary on detection */
        if (np->binary) {
          char src_ip[INET6_ADDRSTRLEN], tgt_ip[INET6_ADDRSTRLEN];
          char src_ha[NOMADCAP6_ETH_ADDRSTRLEN];
          struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *)icmp;

          inet_ntop(AF_INET6, &ip->ip6_src, src_ip, sizeof(src_ip));
          inet_ntop(AF_INET6, &ns->nd_ns_target, tgt_ip, sizeof(tgt_ip));
          snprintf(src_ha, sizeof(src_ha), "%02x:%02x:%02x:%02x:%02x:%02x",
            eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
            eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

          char *args[] = {np->binary, src_ha, src_ip, tgt_ip, NULL};
          NOMADCAP6_STDOUT_V(np, "Executing '%s'...\n", args[0]);
          NOMADCAP6_SYSLOG_V(np, LOG_INFO, "Executing '%s'...\n", args[0]);

          nomadcap_exec(args);
        }

        /* Terminate loop if only looking for one match */
        if (NOMADCAP6_FLAG(np, ONE))
          pcap_breakloop(np->p);
      } else {
        NOMADCAP6_STDOUT_V(np, "Local traffic, ignoring...\n");
        NOMADCAP6_SYSLOG_V(np, LOG_INFO, "Local traffic, ignoring...\n");
      }
    }
  }

  /* Bail */
  if (!nomadcap_loop) pcap_breakloop(np->p);
}

int main(int argc, char *argv[]) {
  nomadcap6_pack_t *np;
  struct pcap_stat ps;
  char errbuf[PCAP_ERRBUF_SIZE], ts[NOMADCAP6_TSLEN];
  int c;

#ifdef USE_LIBJANSSON
  json_t *stats;
#endif /* USE_LIBJANSSON */

  /* Init */
  np = nomadcap6_init(argv[0]);

  /* Bail if there are memory troubles */
  if (np == NULL) {
    fprintf(stderr, "nomadcap6_init: alloc failure\n");

    exit(EXIT_FAILURE);
  }

  /* Parse command line argumemnts */
  while ((c = getopt_long(argc, argv,
                          NOMADCAP6_OPTS,
                          nomadcap6_long_opts,
                          NULL)) != -1) {
    switch (c) {
#ifdef USE_LIBCSV
    case 'O':
      np->flags |= NOMADCAP6_FLAGS_OUI;
      break;
#endif /* USE_LIBCSV */
    case 'A':
      np->flags |= NOMADCAP6_FLAGS_ALLNET;
      break;
    case 'a': /* Process unsolicited neighbor advertisements */
      np->flags |= NOMADCAP6_FLAGS_ANNOUNCE;
      break;
    case 'i':
      np->device = strdup(optarg);
      break;
    case 'n': {
	struct in6_addr addr;
	char *slash = strchr(optarg, '/');
	char *end;
	long plen;

	if (!slash)
	  NOMADCAP6_FAILURE(np, "Invalid IPv6 prefix format (use address/prefix)\n");

	*slash = '\0';
	slash++;

	if (inet_pton(AF_INET6, optarg, &addr) <= 0)
	  NOMADCAP6_FAILURE(np, "Invalid IPv6 address\n");

	plen = strtol(slash, &end, 10);

	if (*slash == '\0' || *end != '\0' || plen < 0 || plen > 128)
	  NOMADCAP6_FAILURE(np, "Invalid IPv6 prefix length\n");

	nomadcap6_add_prefix(np, &addr, plen);

	break;
      }
    case 'f':
      np->flags |= NOMADCAP6_FLAGS_FILE;
      np->filename = strdup(optarg);
      break;
    case 'd': {
      char *end;

      /* Convert user supplied duration using special value 0 for forever */
      long duration = strtol(optarg, &end, 10);

      if (*optarg == '\0' || *end != '\0' || duration < 0)
        NOMADCAP6_FAILURE(np, "Invalid duration: %s\n", optarg);

      np->duration = (uint32_t)duration;
      break;
    }
    case 'v':
      np->flags |= NOMADCAP6_FLAGS_VERBOSE;
      break;
    case '1':
      np->flags |= NOMADCAP6_FLAGS_ONE;
      break;
    case 'x':
      np->binary = strdup(optarg);
      break;
#ifdef USE_LIBJANSSON
    case 'j':
      np->flags |= NOMADCAP6_FLAGS_JSON;
      break;
#endif /* USE_LIBJANSSON */
    case 's':
      np->flags |= NOMADCAP6_FLAGS_SYSLOG;
      break;
    case 't':
      np->flags |= NOMADCAP6_FLAGS_TS;
      break;
    case 'u':
      /* Set timestamp function to gmtime for UTC */
      np->ts_func = gmtime;
      break;
    case 'L':
      nomadcap6_printdevs(np, errbuf);
      NOMADCAP6_SUCCESS(np);
    case 'V':
      NOMADCAP6_STDOUT(np, "%s\n", NOMADCAP6_VERSION);
      NOMADCAP6_SUCCESS(np);
    case 'h':
      nomadcap6_usage(np);
      NOMADCAP6_SUCCESS(np);
    case 420: {
      char *s = optarg;
      char *token;

      while ((token = strtok(s, ",")) != NULL) {
	  s = NULL;

	  unsigned long v = strtoul(token, NULL, 0);

	  if (v > 4095) {
            NOMADCAP6_WARNING(np, "VLAN %s out of range\n", token);
            continue;
	  }

	  if (np->vlan_cnt >= 32) {
            NOMADCAP6_WARNING(np, "VLAN list full (32 max)\n");
            break;
	  }

	  np->vlans[np->vlan_cnt++] = (uint16_t)v;
	}

	break;
      }
    default: /* '?' */
      NOMADCAP6_WARNING(np, "Unknown switch -%c, check -h.\n", optopt);
    }
  }

  nomadcap6_setup(np, errbuf);

  NOMADCAP6_STDOUT(np, "Listening on: %s\n", np->device);

  /* VLANs */
  if (np->vlan_cnt > 0) {
    char vlan_str[512];

    memset(vlan_str, 0, sizeof(vlan_str));

    nomadcap_uint2str(vlan_str,
		     sizeof(vlan_str),
		     np->vlans,
		     np->vlan_cnt,
		     "VLAN(s): ",
		     "\n");

    NOMADCAP6_STDOUT_V(np, "%s", vlan_str);
  }

#ifdef USE_LIBJANSSON
  NOMADCAP6_JSON_PACK(np, "listening_on", json_string(np->device));
#endif /* USE_LIBJANSSON */

  if (NOMADCAP6_FLAG(np, NETWORK))
    nomadcap6_netprint(np);

  NOMADCAP6_STDOUT_V(np, "Syslog: %d\n", NOMADCAP6_FLAG(np, SYSLOG) > 0);

  memset(ts, 0, sizeof(ts));

  nomadcap_iso8601(np->ts_func, ts, sizeof(ts));
  NOMADCAP6_STDOUT(np, "Started at: %s\n", ts);

#ifdef USE_LIBJANSSON
  if (NOMADCAP6_FLAG(np, JSON))
    NOMADCAP6_JSON_PACK(np, "started_at", json_string(ts));
#endif /* USE_LIBJANSSON */

  pcap_loop(np->p, 0, nomadcap6_pcap_handler,
      (u_char *)np);

  if (NOMADCAP6_FLAG(np, VERBOSE) && NOMADCAP6_FLAG_NOT(np, FILE)) {
    if (pcap_stats(np->p, &ps) == -1) {
      NOMADCAP6_STDERR(np, "pcap_stats: %s\n", pcap_geterr(np->p));
    } else {
      NOMADCAP6_STDOUT(np, "\nPackets received: %'d\n", ps.ps_recv);
      NOMADCAP6_STDOUT(np, "Packets dropped: %'d\n", ps.ps_drop);

#ifdef USE_LIBJANSSON
      if (NOMADCAP6_FLAG(np, JSON)) {
        stats = json_object();

        json_object_set_new(stats, "pkts_recv", json_integer(ps.ps_recv));
        json_object_set_new(stats, "pkts_drop", json_integer(ps.ps_drop));

        NOMADCAP6_JSON_PACK(np, "stats", stats);
      }
#endif /* USE_LIBJANSSON */
    }
  }

#ifdef USE_LIBJANSSON
  if (NOMADCAP6_FLAG(np, JSON)) {
    NOMADCAP6_JSON_PACK_V(np, "version", json_string(NOMADCAP6_VERSION));

    nomadcap6_json_print(np);
  }
#endif

  NOMADCAP6_STDOUT_V(np, "Done\n");
  nomadcap6_exit(np, EXIT_SUCCESS);
}

void nomadcap6_finddev(nomadcap6_pack_t *np, char *errbuf) {
  pcap_if_t *devs, *dev;

  NOMADCAP6_STDOUT_V(np, "Looking for interface...\n");

  if (pcap_findalldevs(&devs, errbuf) == -1)
    NOMADCAP6_FAILURE(np, "pcap_findalldevs: %s\n", errbuf);

  if (devs == NULL)
    NOMADCAP6_FAILURE(np, "No interfaces found\n");

  /* Stop at the first non-loopback device with an IPv6 address */
  for (dev = devs; dev != NULL && np->device == NULL; dev = dev->next) {
    for (pcap_addr_t *addr = dev->addresses; addr != NULL; addr = addr->next) {
      if (addr->addr &&
	addr->addr->sa_family == AF_INET6 &&
	strncmp(dev->name, NOMADCAP_LO, 2) != 0) {
	    np->device = strdup(dev->name);
	    break;
        }
    }
  }

  if (np->device == NULL) {
    pcap_freealldevs(devs);

    NOMADCAP6_FAILURE(np, "No suitable interface found\n");
  }

  NOMADCAP6_STDOUT_V(np, "Found interface: %s\n", np->device);

#ifdef USE_LIBJANSSON
  if (NOMADCAP6_FLAG(np, JSON))
    NOMADCAP6_JSON_PACK_V(np, "found_intf", json_string(np->device));
#endif /* USE_LIBJANSSON */

  pcap_freealldevs(devs);
}

void nomadcap6_netprint(nomadcap6_pack_t *np) {
  char prefix_s[INET6_ADDRSTRLEN];

#ifdef USE_LIBJANSSON
  json_t *prefixes_arr = NULL;

  if (NOMADCAP6_FLAG(np, JSON))
    prefixes_arr = json_array();
#endif /* USE_LIBJANSSON */

  for (uint32_t i = 0; i < np->prefix_num; i++) {
    inet_ntop(AF_INET6, &np->prefixes[i].prefix, prefix_s, sizeof(prefix_s));

    NOMADCAP6_STDOUT(np, "Network prefix: %s/%d\n", prefix_s,
        np->prefixes[i].prefixlen);

#ifdef USE_LIBJANSSON
    if (NOMADCAP6_FLAG(np, JSON)) {
      json_t *entry = json_object();

      json_object_set_new(entry, "prefix", json_string(prefix_s));
      json_object_set_new(entry, "prefix_length",
          json_integer(np->prefixes[i].prefixlen));

      json_array_append_new(prefixes_arr, entry);
    }
#endif /* USE_LIBJANSSON */
  }

#ifdef USE_LIBJANSSON
  if (NOMADCAP6_FLAG(np, JSON))
    NOMADCAP6_JSON_PACK(np, "prefixes", prefixes_arr);
#endif /* USE_LIBJANSSON */
}

void nomadcap6_pcap_setup(nomadcap6_pack_t *np, char *errbuf) {
  if (NOMADCAP6_FLAG(np, SYSLOG))
    nomadcap_openlog(np->pname);

  if (NOMADCAP6_FLAG_NOT(np, FILE)) {
    np->p = pcap_open_live(np->device, NOMADCAP6_SNAPLEN, NOMADCAP6_PROMISC,
                           NOMADCAP6_TIMEOUT, errbuf);

    if (np->p == NULL)
      NOMADCAP6_FAILURE(np, "pcap_open_live: %s\n", errbuf);
  } else {
    NOMADCAP6_STDOUT_V(np, "Loading capture file: %s\n", np->filename);

#ifdef USE_LIBJANSSON
    if (NOMADCAP6_FLAG(np, JSON))
      NOMADCAP6_JSON_PACK_V(np, "offline_file", json_string(np->filename));
#endif /* USE_LIBJANSSON */

    np->p = pcap_open_offline(np->filename, errbuf);

    if (np->p == NULL)
      NOMADCAP6_FAILURE(np, "pcap_open_offline: %s\n", errbuf);
  }

  /* Compile filter into BPF program */
  if (pcap_compile(np->p, &np->code, np->filter, 1, PCAP_NETMASK_UNKNOWN) == -1)
    NOMADCAP6_FAILURE(np, "pcap_compile: %s\n", pcap_geterr(np->p));

  if (pcap_setfilter(np->p, &np->code) == -1)
    NOMADCAP6_FAILURE(np, "pcap_setfilter: %s\n", errbuf);

  if (pcap_datalink(np->p) != DLT_EN10MB)
    NOMADCAP6_FAILURE(np, "pcap_datalink: Ethernet only, sorry.");
}

void nomadcap6_signals(nomadcap6_pack_t *np) {
  if (nomadcap_signal(SIGINT, nomadcap_cleanup) == -1)
    NOMADCAP6_FAILURE(np, "Can't catch SIGINT signal\n");

  if (np->duration > 0) {
    NOMADCAP6_STDOUT_V(np, "Duration: %'d seconds\n", np->duration);

#ifdef USE_LIBJANSSON
    if (NOMADCAP6_FLAG(np, JSON))
      NOMADCAP6_JSON_PACK_V(np, "duration", json_integer(np->duration));
#endif /* USE_LIBJANSSON */

    if (nomadcap_signal(SIGALRM, nomadcap_alarm) == -1)
      NOMADCAP6_FAILURE(np, "Can't catch SIGALRM signal\n");

    alarm(np->duration);
  }
}
