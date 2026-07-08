#ifndef __NOMADCAP_COMMON_H
#define __NOMADCAP_COMMON_H

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include <net/ethernet.h>

#include <pcap.h>

/* 802.1Q tag length */
#define NOMADCAP_VLAN_HDRLEN 4

#ifdef USE_LIBCSV
/* IEEE OUI path & files */
#define NOMADCAP_OUI_PATH "/usr/share/ieee-data/"
#define NOMADCAP_OUI_FILE "oui.csv"
#define NOMADCAP_OUI_FILEPATH NOMADCAP_OUI_PATH NOMADCAP_OUI_FILE

/* OUI cache entry size */
#define NOMADCAP_OUI_CSIZE 256

/* Initial OUI dynamic memory allocation */
#define NOMADCAP_OUI_ENTRIES 4096

/* OUI entry */
typedef struct nomadcap_oui {
  char *registry;
  char *assignment;
  char *org_name;
  char *org_address;

  uint32_t count;
} nomadcap_oui_t;

/* IEEE OUI data and lookup cache */
typedef struct nomadcap_oui_table {
  nomadcap_oui_t *data;
  nomadcap_oui_t *cache[NOMADCAP_OUI_CSIZE];

  uint32_t num;
  uint32_t max;
  uint32_t index;

  int oom;
} nomadcap_oui_table_t;

/* Returns 1 on success, 0 if the file can't be opened (soft failure),
   -1 on parse or allocation errors; err holds the failure detail */
int nomadcap_oui_load(nomadcap_oui_table_t *, const char *, char *, size_t);
nomadcap_oui_t *nomadcap_oui_lookup(nomadcap_oui_table_t *, const uint8_t *);
uint32_t nomadcap_oui_size(nomadcap_oui_table_t *);
void nomadcap_oui_free(nomadcap_oui_table_t *);
#endif /* USE_LIBCSV */

/* Termination control, set from signal handlers */
extern volatile sig_atomic_t nomadcap_loop;

/* Capture handle the signal handlers break out of a blocked poll */
extern pcap_t *volatile nomadcap_pcap;

void nomadcap_cleanup(int);
void nomadcap_alarm(int);
int nomadcap_signal(int, void (*)(int));

ssize_t nomadcap_uint2str(char *, size_t, const uint16_t *, size_t,
                          const char *, const char *);
void nomadcap_iso8601(struct tm *(*)(const time_t *), char *, size_t);
void nomadcap_exec(char **);
int nomadcap_vlan_match(const struct ether_header *, const uint16_t *, size_t);

#endif /* __NOMADCAP_COMMON_H */
