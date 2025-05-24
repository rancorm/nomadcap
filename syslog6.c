#include "syslog6.h"

void nomadcap6_openlog(nomadcap6_pack_t *np) {
  openlog(np->pname, LOG_PID | LOG_CONS, LOG_USER);
}

void nomadcap6_syslog(nomadcap6_pack_t *np, int priority, const char *fmt, ...) {
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  syslog(priority, "%s", buf);
}

void nomadcap6_closelog(nomadcap6_pack_t *np) {
  closelog();
}
