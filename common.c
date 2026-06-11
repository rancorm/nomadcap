/*
 *
 * common.c [code shared between nomadcap and nomadcap6]
 *
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <arpa/inet.h>

#ifdef USE_LIBCSV
#include <csv.h>
#endif /* USE_LIBCSV */

#include "common.h"

/* Global termination control, set from signal handlers */
volatile sig_atomic_t nomadcap_loop = 1;

void nomadcap_cleanup(int signo) {
  ssize_t w;

  nomadcap_loop = 0;

  /* write() is async-signal-safe, fprintf() is not */
  w = write(STDERR_FILENO, "Interrupt signal\n", 17);
  (void)w;
  (void)signo;
}

void nomadcap_alarm(int signo) {
  nomadcap_loop = 0;

  (void)signo;
}

int nomadcap_signal(int signo, void (*handler)(int)) {
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

ssize_t nomadcap_uint2str(char *buf, size_t buf_size,
			 const uint16_t *array, size_t count,
			 const char *prefix, const char *suffix) {
  size_t used = 0;
  int w;

  /* prefix */
  w = snprintf(buf + used, buf_size - used, "%s", prefix);

  if (w < 0 || (size_t)w >= buf_size - used)
    return -1;

  used += w;

  /* array elements */
  for (size_t i = 0; i < count; ++i) {
    w = snprintf(buf + used, buf_size - used, "%u", array[i]);

    if (w < 0 || (size_t)w >= buf_size - used)
      return -1;

    used += w;

    if (i + 1 < count) {
      /* comma+space between items */
      w = snprintf(buf + used, buf_size - used, ", ");

      if (w < 0 || (size_t)w >= buf_size - used)
	return -1;

      used += w;
    }
  }

  /* suffix */
  w = snprintf(buf + used, buf_size - used, "%s", suffix);

  if (w < 0 || (size_t)w >= buf_size - used)
    return -1;

  used += w;

  return used;
}

void nomadcap_iso8601(struct tm *(*ts_func)(const time_t *), char *ts,
                      size_t ts_size) {
    time_t rawtime;
    struct tm *timeinfo;
    struct timeval tv;

    /* Get the current time */
    time(&rawtime);

    /* Call timestamp function (localtime or gmtime) */
    timeinfo = ts_func(&rawtime);

    /* Format the time as a string in ISO 8601 format (24-hour clock) */
    strftime(ts, ts_size, "%Y-%m-%dT%H:%M:%S.", timeinfo);

    /* Append milliseconds */
    gettimeofday(&tv, NULL);
    snprintf(ts + 20, ts_size - 20, "%03d", (int)(tv.tv_usec / 1000));

     /* Append timezone offset */
    strftime(ts + 23, ts_size - 23, "%z", timeinfo);
}

void nomadcap_exec(char **argv) {
  pid_t pid = fork();

  if (pid == 0) {
    /* Child process */
    execvp(argv[0], argv);
    _exit(1);
  } else if (pid > 0) {
    /* Parent process */
    int status;
    waitpid(pid, &status, 0);
  } else {
    perror("fork");
  }
}

int nomadcap_vlan_match(const struct ether_header *eh, const uint16_t *vlans,
                        size_t vlan_cnt) {
  /* 1. 0x8100 marks an 802.1Q tag */
  if (ntohs(eh->ether_type) != ETHERTYPE_VLAN)
    return 0;

  /* 2. VLAN tag sits right after ether_type */
  const uint16_t *tci = (const uint16_t *)(eh + 1);

  /* 3. lower 12 bits are the VID */
  uint16_t vid = ntohs(*tci) & 0x0FFF;

  for (size_t i = 0; i < vlan_cnt; i++) {
    if (vid == vlans[i]) {
      return 1;
    }
  }

  return 0;
}

#ifdef USE_LIBCSV
static void nomadcap_oui_cb1(void *field, size_t num, void *data) {
  nomadcap_oui_table_t *t;
  uint32_t index;

  (void)num;

  t = (nomadcap_oui_table_t *)data;

  if (t->oom)
    return;

  /* Entry being filled; rows are committed in _cb2 */
  index = t->num;

  /* Add more memory */
  if (t->num == t->max) {
    nomadcap_oui_t *grown;

    t->max += NOMADCAP_OUI_ENTRIES;
    grown = (nomadcap_oui_t *)realloc(t->data,
        t->max * sizeof(nomadcap_oui_t));

    if (grown == NULL) {
      t->oom = 1;
      return;
    }

    t->data = grown;
  }

  /* Start each row from a clean entry; realloc memory is uninitialized */
  if (t->index == 0)
    memset(&t->data[index], 0, sizeof(nomadcap_oui_t));

  /* Assign field data */
  switch (t->index) {
  case 0:
    t->data[index].registry = strdup(field);
    break;
  case 1:
    t->data[index].assignment = strdup(field);
    break;
  case 2:
    t->data[index].org_name = strdup(field);
    break;
  case 3:
    t->data[index].org_address = strdup(field);
    break;
  default:
    break;
  }

  /* Increase OUI field index for next run */
  t->index++;
}

static void nomadcap_oui_cb2(int num, void *data) {
  nomadcap_oui_table_t *t;
  nomadcap_oui_t *entry;

  (void)num;

  t = (nomadcap_oui_table_t *)data;

  /* Reset field index */
  t->index = 0;

  /* Row ended without any fields parsed */
  if (t->oom || t->num >= t->max)
    return;

  entry = &t->data[t->num];

  /* Skip the CSV header row */
  if (entry->registry && strcmp(entry->registry, "Registry") == 0) {
    free(entry->registry);
    free(entry->assignment);
    free(entry->org_name);
    free(entry->org_address);
    memset(entry, 0, sizeof(*entry));

    return;
  }

  /* End of OUI entry row, increase number of OUIs */
  t->num++;
}

int nomadcap_oui_load(nomadcap_oui_table_t *t, const char *path,
                      char *err, size_t err_size) {
  struct csv_parser cp;
  size_t nbytes;
  char buf[4096];
  FILE *fp;

  /* Open the IEEE OUI CSV file */
  fp = fopen(path, "r");

  if (fp == NULL) {
    snprintf(err, err_size, "%s: %s", path, strerror(errno));

    return 0;
  }

  /* Allocate memory for OUI data */
  t->num = 0;
  t->index = 0;
  t->oom = 0;
  t->max = NOMADCAP_OUI_ENTRIES;
  t->data = (nomadcap_oui_t *)calloc(t->max, sizeof(nomadcap_oui_t));

  if (t->data == NULL) {
    snprintf(err, err_size, "Memory allocation error");
    fclose(fp);

    return -1;
  }

  /* Initialize parser */
  csv_init(&cp, CSV_STRICT | CSV_APPEND_NULL);

  /* Read and parse OUI entries */
  /* Function _cb1 handles fields, _cb2 handles row end */
  while ((nbytes = fread(buf, 1, sizeof(buf), fp)) > 0) {
    if (csv_parse(&cp, buf, nbytes, nomadcap_oui_cb1, nomadcap_oui_cb2, t) !=
        nbytes) {
      snprintf(err, err_size, "Error parsing OUI data file: %s",
          csv_strerror(csv_error(&cp)));
      csv_free(&cp);
      fclose(fp);

      return -1;
    }
  }

  /* Flush remaining row, clean up parser resources, close file */
  csv_fini(&cp, nomadcap_oui_cb1, nomadcap_oui_cb2, t);
  csv_free(&cp);
  fclose(fp);

  if (t->oom) {
    snprintf(err, err_size, "Memory allocation error");

    return -1;
  }

  return 1;
}

nomadcap_oui_t *nomadcap_oui_lookup(nomadcap_oui_table_t *t,
                                    const uint8_t *mac) {
  char oui[7], *assignment;
  uint32_t index;
  int cindex;

  /* Convert to char[] for string compare */
  snprintf(oui, sizeof(oui), "%02X%02X%02X", mac[0], mac[1], mac[2]);

  /* Check OUI cache for a match */
  for (cindex = 0; cindex < NOMADCAP_OUI_CSIZE && t->cache[cindex]; cindex++) {
    if (strncmp(oui, t->cache[cindex]->assignment, 6) == 0) {
      /* Increment cache OUI entry count */
      t->cache[cindex]->count++;

      return t->cache[cindex];
    }
  }

  /* Loop through OUI entries looking for a match */
  for (index = 0; index < t->num; index++) {
    assignment = t->data[index].assignment;

    /* Malformed row with missing assignment field */
    if (assignment == NULL)
      continue;

    /* Increment entry count and return the entry */
    if (strncmp(oui, assignment, 6) == 0) {
      t->data[index].count++;

      /* Find first empty cache slot */
      cindex = 0;
      while (cindex < NOMADCAP_OUI_CSIZE && t->cache[cindex])
        cindex++;

      /* Cache is full, replace random cache entry */
      if (cindex == NOMADCAP_OUI_CSIZE)
        cindex = rand() % NOMADCAP_OUI_CSIZE;

      /* Insert found OUI entry to cache */
      t->cache[cindex] = &t->data[index];

      return &t->data[index];
    }
  }

  return NULL;
}

uint32_t nomadcap_oui_size(nomadcap_oui_table_t *t) { return t->num; }

void nomadcap_oui_free(nomadcap_oui_table_t *t) {
  if (t->data == NULL)
    return;

  for (uint32_t i = 0; i < t->num; i++) {
    free(t->data[i].registry);
    free(t->data[i].assignment);
    free(t->data[i].org_name);
    free(t->data[i].org_address);
  }

  free(t->data);
  t->data = NULL;
  t->num = 0;
  t->max = 0;
}
#endif /* USE_LIBCSV */
