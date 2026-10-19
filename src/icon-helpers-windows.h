#include "idun.h"

#ifndef __IDUN_ICON_HELPERS_WINDOWS_H__
#define __IDUN_ICON_HELPERS_WINDOWS_H__

#define VC_EXTRALEAN
#include <windows.h>
#undef VC_EXTRALEAN

typedef enum _IdunIconSize IdunIconSize;

enum _IdunIconSize
{
  IDUN_ICON_SMALL,
  IDUN_ICON_LARGE
};

GVariant * _idun_icon_from_process_or_file (DWORD pid, WCHAR * filename, IdunIconSize size);

GVariant * _idun_icon_from_process (DWORD pid, IdunIconSize size);
GVariant * _idun_icon_from_file (WCHAR * filename, IdunIconSize size);
GVariant * _idun_icon_from_resource_url (WCHAR * resource_url, IdunIconSize size);

GVariant * _idun_icon_from_native_icon_handle (HICON icon, IdunIconSize size);

#endif
