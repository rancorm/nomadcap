#include <stdio.h>

#include "syslog.h"

void nomadcap_openlog(const char *pname) {
  openlog(pname, LOG_PID | LOG_CONS, LOG_USER);
}

void nomadcap_syslog(int priority, const char *fmt, ...) {
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  syslog(priority, "%s", buf);
}

void nomadcap_closelog(void) {
  closelog();
}
