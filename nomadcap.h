#ifndef __NOMADCAP_H
#define __NOMADCAP_H

/* Author and banner */
#define NOMADCAP_AUTHOR "Jonathan Cormier <jonathan@cormier.co>"
#define NOMADCAP_BANNER "Misconfigure network stack identification tool"

/* Application defaults */
#define NOMADCAP_DURATION 60

/* PCAP stuff */
/* Ethernet ARP broadcast requests */
#define NOMADCAP_FILTER "arp"
#define NOMADCAP_SNAPLEN 64
#define NOMADCAP_TIMEOUT 500
#define NOMADCAP_PROMISC 0 

/* IP address for all zeros */
#define NOMADCAP_NONE "\x00\x00\x00\x00"

/* MAC addresses for unknown and broadcast frames */
#define NOMADCAP_UNKNOWN "\x00\x00\x00\x00\x00\x00"
#define NOMADCAP_BROADCAST "\xff\xff\xff\xff\xff\xff"

/*
Application flags:

L - List interfaces
O - OUI look up
A - Monitor for all networks
p - Process ARP probes
a - Process ARP announcments
i - Specific interface
n - Capture network
m - Capture subnet
f - Offline capture file
d - Capture duration time
h - Help screen
v - Verbose mode
V - Version
1 - Single match
j - JSON mode
t - ISO 8601 timestamps
*/
#define NOMADCAP_OPTS "LOApai:n:m:f:d:hvV1x:jtu"

static const struct option nomadcap_long_opts[] = {
#ifdef USE_LIBCSV
  { "oui",      no_argument,       NULL, 'O' },
#endif
  { "all",       no_argument,       NULL, 'A' },
  { "probes",    no_argument,       NULL, 'p' },
  { "announce",  no_argument,       NULL, 'a' },
  { "interface", required_argument, NULL, 'i' },
  { "network",   required_argument, NULL, 'n' },
  { "netmask",   required_argument, NULL, 'm' },
  { "file",      required_argument, NULL, 'f' },
  { "duration",  required_argument, NULL, 'd' },
  { "verbose",   no_argument,       NULL, 'v' },
  { "once",      no_argument,       NULL, '1' },
  { "exec",      required_argument, NULL, 'x' },
#ifdef USE_LIBJANSSON
  { "json",      no_argument,       NULL, 'j' },
#endif
  { "timestamp", no_argument,       NULL, 't' },
  { "utc",       no_argument,       NULL, 'u' },
  { "list",      no_argument,       NULL, 'L' },
  { "version",   no_argument,       NULL, 'V' },
  { "help",      no_argument,       NULL, 'h' },
  { 0, 0, 0, 0 }
};

#define NOMADCAP_FLAG(pack, flag) (pack->flags & NOMADCAP_FLAGS_##flag)
#define NOMADCAP_FLAG_NOT(pack, flag)                                          \
  ((pack->flags & NOMADCAP_FLAGS_##flag) == 0)
#define NOMADCAP_FLAGS_NONE 0x0
#define NOMADCAP_FLAGS_VERBOSE 0x1
#define NOMADCAP_FLAGS_ALLNET 0x2
#define NOMADCAP_FLAGS_PROBES 0x4
#define NOMADCAP_FLAGS_ANNOUNCE 0x10
#define NOMADCAP_FLAGS_FILE 0x20
#define NOMADCAP_FLAGS_ONE 0x40
#define NOMADCAP_FLAGS_NETWORK 0x100
#define NOMADCAP_FLAGS_NETMASK 0x200

#ifdef USE_LIBCSV
#define NOMADCAP_FLAGS_OUI 0x400

/* IEEE OUI path & files */
#define NOMADCAP_OUI_PATH "/usr/share/ieee-data/"
#define NOMADCAP_OUI_FILE "oui.csv"
#define NOMADCAP_OUI_FILEPATH NOMADCAP_OUI_PATH NOMADCAP_OUI_FILE

/* OUI cache entry size */
#define NOMADCAP_OUI_CSIZE 256

/* Initial OUI dynamic memory allocation */
#define NOMADCAP_OUI_ENTRIES 4096
#endif /* USE_LIBCSV */

#ifdef USE_LIBJANSSON
#define NOMADCAP_FLAGS_JSON 0x1000
#endif /* USE_LIBJANSSON */

#define NOMADCAP_FLAGS_TS 0x2000

#define NOMADCAP_VERSION "0.3"

/* OUI entry */
typedef struct nomadcap_oui {
  char *registry;
  char *assignment;
  char *org_name;
  char *org_address;

  uint32_t count;
} nomadcap_oui_t;

/* Application state package */
typedef struct nomadcap_pack {
  /* Capture device, filter, filename, and duration */
  char *device;
  char *filter;
  char *filename;
  uint32_t duration;

  /* Application running name */
  char *pname;

  /* Flags that control application logic */
  uint16_t flags;

#ifdef USE_LIBCSV
  /* IEEE OUI data */
  nomadcap_oui_t *oui_data;
  nomadcap_oui_t *oui_cache[NOMADCAP_OUI_CSIZE];

  uint32_t oui_num;
  uint32_t oui_max;
  uint32_t oui_index;
#endif /* USE_LIBCSV */

#ifdef USE_LIBJANSSON
  json_t *json;
#endif /* USE_LIBJANSSON */

  /* PCAP */
  pcap_t *p;
  struct bpf_program code;

  /* Timestamp function pointer (localtime or gmtime)*/
  struct tm *(*ts_func)(const time_t *);

  bpf_u_int32 localnet, netmask;

  /* Path to binary */
  char *binary;
} nomadcap_pack_t;

#ifdef USE_LIBJANSSON
#define NOMADCAP_STDERR(pack, format, ...)                                     \
  do {                                                                         \
    if (NOMADCAP_FLAG_NOT(pack, JSON)) {                                       \
      fprintf(stderr, format __VA_OPT__(, ) __VA_ARGS__);                      \
    }                                                                          \
  } while (0)

#define NOMADCAP_STDOUT(pack, format, ...)                                     \
  do {                                                                         \
    if (NOMADCAP_FLAG_NOT(pack, JSON)) {                                       \
      printf(format __VA_OPT__(, ) __VA_ARGS__);                               \
    }                                                                          \
  } while (0)

#define NOMADCAP_STDOUT_V(pack, format, ...)                                   \
  do {                                                                         \
    if (NOMADCAP_FLAG(pack, VERBOSE) && NOMADCAP_FLAG_NOT(pack, JSON)) {       \
      printf(format __VA_OPT__(, ) __VA_ARGS__);                               \
    }                                                                          \
  } while (0)

#define NOMADCAP_WARNING(pack, format, ...)                                    \
  do {                                                                         \
    if (NOMADCAP_FLAG_NOT(pack, JSON)) {                                       \
      fprintf(stderr, format  __VA_OPT__(, ) __VA_ARGS__);                     \
    }                                                                          \
  } while(0)

#define NOMADCAP_JSON_PACK(pack, name, value)                                  \
  do {                                                                         \
    json_object_set_new(pack->json, name, value);                              \
  } while (0)

#define NOMADCAP_JSON_PACK_V(pack, name, value)                                \
  do {                                                                         \
    if (NOMADCAP_FLAG(pack, VERBOSE)) {                                        \
      json_object_set_new(pack->json, name, value);                            \
    }                                                                          \
  } while (0)

#else
#define NOMADCAP_STDERR(pack, format, ...)                                     \
  do {                                                                         \
    fprintf(stderr, format __VA_OPT__(, ) __VA_ARGS__);                        \
  } while (0)

#define NOMADCAP_STDOUT(pack, format, ...)                                     \
  do {                                                                         \
      printf(format __VA_OPT__(, ) __VA_ARGS__);                               \
  } while (0)

#define NOMADCAP_STDOUT_V(pack, format, ...)                                   \
  do {                                                                         \
    if (NOMADCAP_FLAG(pack, VERBOSE)) {                                        \
      printf(format __VA_OPT__(, ) __VA_ARGS__);                               \
    }                                                                          \
  } while (0)

#define NOMADCAP_WARNING(pack, format, ...)                                    \
  do {                                                                         \
    fprintf(stderr, format  __VA_OPT__(, ) __VA_ARGS__);                       \
  } while(0)
#endif /* USE_LIBJANSSON */

#define NOMADCAP_FAILURE(pack, format, ...)                                    \
  do {                                                                         \
    fprintf(stderr, format __VA_OPT__(, ) __VA_ARGS__);                        \
    nomadcap_exit(pack, EXIT_FAILURE);                                         \
  } while (0)

#define NOMADCAP_SUCCESS(pack)                                                 \
  do {                                                                         \
    nomadcap_exit(pack, EXIT_SUCCESS);                                         \
  } while (0)

#define NOMADCAP_HELP_COLS 23
#define NOMADCAP_HELP_DESC 20
#define STR(x)  #x
#define XSTR(x) STR(x)
#define NOMADCAP_HELP_OPT(pack, opt, desc)		      		       \
  do {									       \
    printf("  %-*s%-*s\n",						       \
      NOMADCAP_HELP_COLS,						       \
      opt,								       \
      NOMADCAP_HELP_DESC,						       \
      desc);								       \
  } while (0)

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif /* ETH_ALEN */

/* Ethernet address string length (octets + colons + null)*/
#define NOMADCAP_ETH_ADDRSTRLEN (12 + 5 + 1)

/* ISO 8601 timestamp string length */
#define NOMADCAP_TSLEN 29

#define NOMADCAP_LO "lo"

/* Function prototypes */
#ifdef USE_LIBJANSSON
int nomadcap_oui_load(nomadcap_pack_t *, char *);
nomadcap_oui_t *nomadcap_oui_lookup(nomadcap_pack_t *, struct ether_arp *);
uint32_t nomadcap_oui_size(nomadcap_pack_t *);
#endif /* USE_LIBJANSSON */

void nomadcap_finddev(nomadcap_pack_t *, char *);
void nomadcap_signals(nomadcap_pack_t *);
void nomadcap_pcap_setup(nomadcap_pack_t *, char *);
void nomadcap_netprint(nomadcap_pack_t *);

#endif /* __NOMADCAP_H */
