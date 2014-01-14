#include <stdlib.h>

#include "vtcapi_common.h"

int debug_level = 9;

void VtDebug_setDebugLevel(int level)
{
	debug_level = level;
}

static void __init__(102) VtDebug_init(void)
{
	char *level = getenv("VT_DEBUG");
	if (level) {
		debug_level = atoi(level);
	}
}
