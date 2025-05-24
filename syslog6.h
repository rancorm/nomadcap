#ifndef __SYSLOG6_H
#define __SYSLOG6_H

#include <stdarg.h>
#include <syslog.h>

#include "nomadcap6.h"

void nomadcap6_openlog(nomadcap6_pack_t *);
void nomadcap6_syslog(nomadcap6_pack_t *, int, const char *, ...);
void nomadcap6_closelog(nomadcap6_pack_t *);

#endif /* __SYSLOG6_H */
