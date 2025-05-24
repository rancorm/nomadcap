#ifndef __NOMADCAP6_H
#define __NOMADCAP6_H

#include "nomadcap.h"


/* Author and banner */
#define NOMADCAP6_AUTHOR NOMADCAP_AUTHOR
#define NOMADCAP6_BANNER "Misconfigure v6 network stack identification tool"

/* Application defaults */
#define NOMADCAP6_DURATION 60

/* Initial prefix dynamic memory allocation */
#define NOMADCAP6_PREFIX_ENTRIES 8

/* PCAP stuff */
/* ICMPv6 */
#define NOMADCAP6_FILTER "icmp6"
#define NOMADCAP6_SNAPLEN 128
#define NOMADCAP6_TIMEOUT 500
#define NOMADCAP6_PROMISC 0 

/* MAC addresses for unknown and broadcast frames */
#define NOMADCAP6_UNKNOWN "\x00\x00\x00\x00\x00\x00"
#define NOMADCAP6_BROADCAST "\xff\xff\xff\xff\xff\xff"

/*
Application flags:

L - List interfaces
O - OUI look up
A - Monitor for all networks
i - Specific interface
n - Capture network
f - Offline capture file
d - Capture duration time
h - Help screen
v - Verbose mode
V - Version
1 - Single match
j - JSON mode
t - ISO 8601 timestamps
u - UTC timestamps
*/
#define NOMADCAP6_OPTS "LOAi:n:f:d:hvV1x:jtsu"

static const struct option nomadcap6_long_opts[] = {
#ifdef USE_LIBCSV
  { "oui",       no_argument,       NULL, 'O' },
#endif
  { "all",       no_argument,       NULL, 'A' },
  { "interface", required_argument, NULL, 'i' },
  { "network",   required_argument, NULL, 'n' },
  { "vlan",      required_argument, NULL, 420 },
  { "file",      required_argument, NULL, 'f' },
  { "duration",  required_argument, NULL, 'd' },
  { "verbose",   no_argument,       NULL, 'v' },
  { "once",      no_argument,       NULL, '1' },
  { "exec",      required_argument, NULL, 'x' },
#ifdef USE_LIBJANSSON
  { "json",      no_argument,       NULL, 'j' },
#endif
  { "syslog",    no_argument,       NULL, 's' },
  { "timestamp", no_argument,       NULL, 't' },
  { "utc",       no_argument,       NULL, 'u' },
  { "list",      no_argument,       NULL, 'L' },
  { "version",   no_argument,       NULL, 'V' },
  { "help",      no_argument,       NULL, 'h' },
  { 0, 0, 0, 0 }
};

#define NOMADCAP6_FLAG(pack, flag) (pack->flags & NOMADCAP6_FLAGS_##flag)
#define NOMADCAP6_FLAG_NOT(pack, flag)                                          \
  ((pack->flags & NOMADCAP6_FLAGS_##flag) == 0)
#define NOMADCAP6_FLAGS_NONE 0x0
#define NOMADCAP6_FLAGS_VERBOSE 0x1
#define NOMADCAP6_FLAGS_ALLNET 0x2
#define NOMADCAP6_FLAGS_FILE 0x4
#define NOMADCAP6_FLAGS_ONE 0x8
#define NOMADCAP6_FLAGS_ANNOUNCE 0x10
#define NOMADCAP6_FLAGS_NETWORK 0x20

#ifdef USE_LIBCSV
#define NOMADCAP6_FLAGS_OUI 0x400

/* IEEE OUI path & files */
#define NOMADCAP6_OUI_PATH NOMADCAP_OUI_PATH
#define NOMADCAP6_OUI_FILE NOMADCAP_OUI_FILE
#define NOMADCAP6_OUI_FILEPATH NOMADCAP6_OUI_PATH NOMADCAP6_OUI_FILE

/* OUI cache entry size */
#define NOMADCAP6_OUI_CSIZE 256

/* Initial OUI dynamic memory allocation */
#define NOMADCAP6_OUI_ENTRIES 4096
#endif /* USE_LIBCSV */

#ifdef USE_LIBJANSSON
#define NOMADCAP6_FLAGS_JSON 0x1000
#endif /* USE_LIBJANSSON */

#define NOMADCAP6_FLAGS_TS 0x2000
#define NOMADCAP6_FLAGS_SYSLOG 0x4000

#define NOMADCAP6_VERSION NOMADCAP_VERSION

/* IPv6 prefix entry */
typedef struct nomadcap6_prefix {
  struct in6_addr prefix;
  int prefixlen;
} nomadcap6_prefix_t;

/* OUI entry */
typedef struct nomadcap6_oui {
  char *registry;
  char *assignment;
  char *org_name;
  char *org_address;

  uint32_t count;
} nomadcap6_oui_t;

/* Application state package */
typedef struct nomadcap6_pack {
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
  nomadcap6_oui_t *oui_data;
  nomadcap6_oui_t *oui_cache[NOMADCAP6_OUI_CSIZE];

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

  nomadcap6_prefix_t *prefixes;
  uint32_t prefix_num;
  uint32_t prefix_max;

  /* VLAN */
  uint16_t vlans[NOMADCAP_VLANS_SIZE];
  uint8_t vlan_cnt;

  /* Path to binary */
  char *binary;
} nomadcap6_pack_t;

#ifdef USE_LIBJANSSON
#define NOMADCAP6_STDERR(pack, format, ...)                                     \
  do {                                                                         \
    if (NOMADCAP6_FLAG_NOT(pack, JSON)) {                                       \
      fprintf(stderr, format __VA_OPT__(, ) __VA_ARGS__);                      \
    }                                                                          \
  } while (0)

#define NOMADCAP6_STDOUT(pack, format, ...)                                     \
  do {                                                                         \
    if (NOMADCAP6_FLAG_NOT(pack, JSON)) {                                       \
      printf(format __VA_OPT__(, ) __VA_ARGS__);                               \
    }                                                                          \
  } while (0)

#define NOMADCAP6_STDOUT_V(pack, format, ...)                                   \
  do {                                                                         \
    if (NOMADCAP6_FLAG(pack, VERBOSE) && NOMADCAP6_FLAG_NOT(pack, JSON)) {       \
      printf(format __VA_OPT__(, ) __VA_ARGS__);                               \
    }                                                                          \
  } while (0)

#define NOMADCAP6_WARNING(pack, format, ...)                                    \
  do {                                                                         \
    if (NOMADCAP6_FLAG_NOT(pack, JSON)) {                                       \
      fprintf(stderr, format  __VA_OPT__(, ) __VA_ARGS__);                     \
    }                                                                          \
  } while(0)

#define NOMADCAP6_JSON_PACK(pack, name, value)                                  \
  do {                                                                         \
    json_object_set_new(pack->json, name, value);                              \
  } while (0)

#define NOMADCAP6_JSON_PACK_V(pack, name, value)                                \
  do {                                                                         \
    if (NOMADCAP6_FLAG(pack, VERBOSE)) {                                        \
      json_object_set_new(pack->json, name, value);                            \
    }                                                                          \
  } while (0)

#else
#define NOMADCAP6_STDERR(pack, format, ...)                                     \
  do {                                                                         \
    fprintf(stderr, format __VA_OPT__(, ) __VA_ARGS__);                        \
  } while (0)

#define NOMADCAP6_STDOUT(pack, format, ...)                                     \
  do {                                                                         \
      printf(format __VA_OPT__(, ) __VA_ARGS__);                               \
  } while (0)

#define NOMADCAP6_STDOUT_V(pack, format, ...)                                   \
  do {                                                                         \
    if (NOMADCAP6_FLAG(pack, VERBOSE)) {                                        \
      printf(format __VA_OPT__(, ) __VA_ARGS__);                               \
    }                                                                          \
  } while (0)

#define NOMADCAP6_WARNING(pack, format, ...)                                    \
  do {                                                                         \
    fprintf(stderr, format  __VA_OPT__(, ) __VA_ARGS__);                       \
  } while(0)
#endif /* USE_LIBJANSSON */

#define NOMADCAP6_SYSLOG(pack, format, ...)				       \
  do {									       \
    if (NOMADCAP6_FLAG(pack, SYSLOG)) {					       \
      nomadcap6_syslog(pack, format __VA_OPT__(, ) __VA_ARGS__);	       \
    }									       \
  } while(0)

#define NOMADCAP6_SYSLOG_V(pack, format, ...)				       \
  do {									       \
    if (NOMADCAP6_FLAG(pack, SYSLOG) &&					       \
      NOMADCAP6_FLAG(pack, VERBOSE)) {					       \
      nomadcap6_syslog(pack, format __VA_OPT__(, ) __VA_ARGS__);	       \
    }									       \
  } while(0)

#define NOMADCAP6_FAILURE(pack, format, ...)                                    \
  do {                                                                         \
    fprintf(stderr, format __VA_OPT__(, ) __VA_ARGS__);                        \
    nomadcap6_exit(pack, EXIT_FAILURE);                                         \
  } while (0)

#define NOMADCAP6_SUCCESS(pack)                                                 \
  do {                                                                         \
    nomadcap6_exit(pack, EXIT_SUCCESS);                                         \
  } while (0)


/* Ethernet address string length (octets + colons + null)*/
#define NOMADCAP6_ETH_ADDRSTRLEN NOMADCAP_ETH_ADDRSTRLEN

/* ISO 8601 timestamp string length */
#define NOMADCAP6_TSLEN NOMADCAP_TSLEN

/* Function prototypes */
#ifdef USE_LIBCSV
int nomadcap6_oui_load(nomadcap6_pack_t *, char *);
nomadcap6_oui_t *nomadcap6_oui_lookup(nomadcap6_pack_t *, uint8_t *);
uint32_t nomadcap6_oui_size(nomadcap6_pack_t *);
#endif /* USE_LIBCSV */

void nomadcap6_add_prefix(nomadcap6_pack_t *, struct in6_addr *, int);
int nomadcap6_isvlan(nomadcap6_pack_t *, struct ether_header *);
void nomadcap6_finddev(nomadcap6_pack_t *, char *);
void nomadcap6_signals(nomadcap6_pack_t *);
void nomadcap6_pcap_setup(nomadcap6_pack_t *, char *);
void nomadcap6_netprint(nomadcap6_pack_t *);

#define NOMADCAP6_HELP_OPT(pack, opt, desc) NOMADCAP_HELP_OPT(pack, opt, desc)

#endif /* __NOMADCAP6_H */
