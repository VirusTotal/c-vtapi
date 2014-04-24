/*
Copyright 2014 VirusTotal S.L. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdlib.h>

#include "vtcapi_common.h"

int debug_level = 0;

void VtDebug_setDebugLevel(int level) {
  debug_level = level;
}

#if 0
static void __init__(102) VtDebug_init(void) {
  char *level = getenv("VT_DEBUG");
  if (level) {
    debug_level = atoi(level);
  }
}
#endif