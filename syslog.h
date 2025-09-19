#ifndef __SYSLOG_H
#define __SYSLOG_H

#include <stdarg.h>
#include <syslog.h>

#include "nomadcap.h"

void nomadcap_openlog(nomadcap_pack_t *);
void nomadcap_syslog(nomadcap_pack_t *, int, const char *, ...);
void nomadcap_closelog(nomadcap_pack_t *);

#endif /* __SYSLOG_H */
