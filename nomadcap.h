#ifndef __NOMADCAP_H
#define __NOMADCAP_H

/* Author and banner */
#define NOMADCAP_AUTHOR "Jonathan Cormier <jonathan@cormier.co>"
#define NOMADCAP_BANNER "Mis-configured network stack tool"

/* IEEE OUI path & files */
#define NOMADCAP_OUI_PATH "/usr/share/ieee-data/"
#define NOMADCAP_OUI_FILE NOMADCAP_OUI_PATH ## "oui.csv"

/* PCAP stuff */
/* Ethernet ARP broadcast requests */
#define NOMADCAP_FILTER "arp" 
#define NOMADCAP_SNAPLEN 64
#define NOMADCAP_TIMEOUT 500
#define NOMADCAP_PROMISC 1 

/* IP address for all zeros */
#define NOMADCAP_NONE "\x00\x00\x00\x00"

/* MAC addresses for unknown and broadcast frames */
#define NOMADCAP_UNKNOWN "\x00\x00\x00\x00\x00\x00"
#define NOMADCAP_BROADCAST "\xff\xff\xff\xff\xff\xff" 

/* Application specific */
#define NOMADCAP_OPTS "OApai:hvV"

#define NOMADCAP_FLAG(pack, flag) (pack.flags & NOMADCAP_FLAGS_ ## flag)
#define NOMADCAP_FLAGS_NONE 0x0
#define NOMADCAP_FLAGS_VERB 0x1
#define NOMADCAP_FLAGS_ALLNET 0x2
#define NOMADCAP_FLAGS_PROBES 0x4
#define NOMADCAP_FLAGS_ANNOUC 0x8
#define NOMADCAP_FLAGS_OUI 0x16

#define NOMADCAP_VERSION "0.1"

/* Package */
typedef struct nomadcap_pack {
    char *device;
    char *filter;
    uint8_t flags;

    /* PCAP */
    pcap_t *p;
    struct pcap_pkthdr ph;
    struct bpf_program code;

    bpf_u_int32 localnet, netmask;
} nomadcap_pack_t;

#define NOMADCAP_PRINTF(pack, format, ...) \
  do { \
    if (pack.flags & NOMADCAP_FLAGS_VERB) { \
        fprintf(stderr, format __VA_OPT__(,) __VA_ARGS__); \
    } \
  } while (0)

#endif /* __NOMADCAP_H */