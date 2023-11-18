#ifndef __NOMADCAP_H
#define __NOMADCAP_H

/* IEEE OUI path & files */
#define NOMADCAP_OUI_PATH "/usr/share/ieee-data/"
#define NOMADCAP_OUI_FILE NOMADCAP_OUI_PATH ## "oui.csv"

/* PCAP stuff */
/* Ethernet ARP broadcast requests */
#define NOMADCAP_FILTER "arp" 
#define NOMADCAP_SNAPLEN 64
#define NOMADCAP_TIMEOUT 500
#define NOMADCAP_PROMISC 1 

#define NOMADCAP_BROADCAST "\xff\xff\xff\xff\xff\xff" 
#define NOMADCAP_OPTS "i:hvV"

#define NOMADCAP_VERSION "0.1"

#define NOMADCAP_FLAGS_NONE 0
#define NOMADCAP_FLAGS_VERB 0x1

/* Package */
typedef struct nomadcap_pack {
    char *device;
    char *filter;
    unsigned char flags;

    /* PCAP */
    pcap_t *p;
    struct pcap_pkthdr ph;
    struct bpf_program code;

    bpf_u_int32 localnet, netmask;
} nomadcap_pack_t;

#endif /* __NOMADCAP_H */