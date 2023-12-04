#ifndef __NOMADCAP_H
#define __NOMADCAP_H

/* Author and banner */
#define NOMADCAP_AUTHOR           "Jonathan Cormier <jonathan@cormier.co>"
#define NOMADCAP_BANNER           "Mis-configured network stack identification tool"

/* Application defaults */
#define NOMADCAP_DURATION         60

/* IEEE OUI path & files */
#define NOMADCAP_OUI_PATH         "/usr/share/ieee-data/"
#define NOMADCAP_OUI_FILE         "oui.csv"
#define NOMADCAP_OUI_FILEPATH     NOMADCAP_OUI_PATH NOMADCAP_OUI_FILE
#define NOMADCAP_OUI_MAXLINE      1024

/* PCAP stuff */
/* Ethernet ARP broadcast requests */
#define NOMADCAP_FILTER           "arp"
#define NOMADCAP_SNAPLEN          64
#define NOMADCAP_TIMEOUT          500
#define NOMADCAP_PROMISC          1

/* IP address for all zeros */
#define NOMADCAP_NONE             "\x00\x00\x00\x00"

/* MAC addresses for unknown and broadcast frames */
#define NOMADCAP_UNKNOWN          "\x00\x00\x00\x00\x00\x00"
#define NOMADCAP_BROADCAST        "\xff\xff\xff\xff\xff\xff"

/* Application specific */
#define NOMADCAP_OPTS             "OApai:f:d:hvV"

#define NOMADCAP_FLAG(pack, flag) (pack->flags & NOMADCAP_FLAGS_ ## flag)
#define NOMADCAP_FLAG_NOT(pack, flag) ((pack->flags & NOMADCAP_FLAGS_ ## flag) == 0)
#define NOMADCAP_FLAGS_NONE       0x0
#define NOMADCAP_FLAGS_VERB       0x1
#define NOMADCAP_FLAGS_ALLNET     0x2
#define NOMADCAP_FLAGS_PROBES     0x4
#define NOMADCAP_FLAGS_ANNOUNCE   0x8
#define NOMADCAP_FLAGS_OUI        0x10
#define NOMADCAP_FLAGS_FILE       0x20

#define NOMADCAP_VERSION          "0.1"

/* OUI entry */
typedef struct nomadcap_oui {
  char *registry;
  char *assignment;
  char *org_name;
  char *org_address;
} nomadcap_oui_t;

/* Application state package */
typedef struct nomadcap_pack {
  /* Capture device, filter, filename, and duration */
  char *device;
  char *filter;
  char *filename;
  uint duration;

  /* Application running name */
  char *pname;

  /* Flags that control application logic */
  uint8_t flags;

  /* IEEE OUI data */
  nomadcap_oui_t **ouis;

  /* PCAP */
  pcap_t *p;
  struct pcap_pkthdr ph;
  struct bpf_program code;

  bpf_u_int32 localnet, netmask;
} nomadcap_pack_t;

#define NOMADCAP_STDERR(pack, format, ...) \
  do { \
    fprintf(stderr, format __VA_OPT__(,) __VA_ARGS__); \
  } while (0)

#define NOMADCAP_STDOUT(pack, format, ...) \
  do { \
    if (NOMADCAP_FLAG(pack, VERB)) { \
        printf(format __VA_OPT__(,) __VA_ARGS__); \
    } \
  } while (0)

#endif /* __NOMADCAP_H */
