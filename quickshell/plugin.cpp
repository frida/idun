#include "plugin.h"

#include "idunscreen.h"

#include <qqml.h>

void IdunScreenPlugin::registerTypes(const char *uri)
{
    qmlRegisterType<IdunScreen>(uri, 1, 0, "IdunScreen");
}
