#define _GNU_SOURCE

#include "idun.h"

#include <dlfcn.h>

gchar *
_idun_daemon_query_library_path (void)
{
  Dl_info info;

  dladdr (_idun_daemon_query_library_path, &info);

  return g_strdup (info.dli_fname);
}
