#ifndef __SYSLOG_H
#define __SYSLOG_H

#include <stdarg.h>
#include <syslog.h>

void nomadcap_openlog(const char *);
void nomadcap_syslog(int, const char *, ...);
void nomadcap_closelog(void);

#endif /* __SYSLOG_H */
