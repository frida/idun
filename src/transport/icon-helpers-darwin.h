#include "idun.h"

#ifndef __IDUN_ICON_HELPERS_DARWIN_H__
#define __IDUN_ICON_HELPERS_DARWIN_H__

typedef gpointer IdunNativeImage;

GVariant * _idun_icon_from_file (const gchar * filename, guint target_width, guint target_height);
GVariant * _idun_icon_from_native_image_scaled_to (IdunNativeImage native_image, guint target_width, guint target_height);

#endif
