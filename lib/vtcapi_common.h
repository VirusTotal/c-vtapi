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

#ifndef VT_COMMON_H
#define VT_COMMON_H

#ifdef HAVE_CONFIG_H
#include "c-vtapi_config.h"
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined (WIN32)
#include <windows.h>
#define WINDOWS 1
#endif

#include <stdio.h>
#include <assert.h>
#if !defined(_WIN32) && !defined(_WIN64)
#include <syslog.h>
#endif

//#if !defined(WINDOWS)
//#include <pthread.h>
//#endif

#define BUG()                \
  do {                 \
    fprintf(stderr, "BUG: %s:%d\n",  \
            __FILE__, __LINE__);         \
    fflush(stderr); \
    fflush(stdout); \
    assert(0);	\
  } while (0)
//
#define PROG_NAME "c-vtapi"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#ifdef _MSC_VER
#define PRINT(FMT,  ...)  printf(PROG_NAME": " FMT, __VA_ARGS__);
#else
#define PRINT(FMT,ARG...) printf(PROG_NAME": " FMT, ##ARG);
#endif

#define VT_API_BASE_URL "https://www.virustotal.com/vtapi/v2/"


extern int debug_level;
#ifdef STATIC_DEBUG
#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 9
#endif
#define DBG(LVL,FMT,ARG...) \
  if (LVL <= DEBUG_LEVEL) {\
    fprintf(stderr, PROG_NAME"<" #LVL ">:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
  }
#else
/*Dynamic debug levels */
#define DEBUG_LEVEL debug_level

#ifdef WINDOWS
#define LOCK_MUTEX(m)   WaitForSingleObject(m, INFINITE)
#define UNLOCK_MUTEX(m) ReleaseMutex(m)
#else
#define LOCK_MUTEX(m)   pthread_mutex_lock(m)
#define UNLOCK_MUTEX(m) pthread_mutex_unlock(m)
#endif



#ifdef _MSC_VER
#define DBG(LVL,FMT, ...) \
  if (LVL <= debug_level) { \
    fprintf(stderr, PROG_NAME"<%d>:%s:%d: " FMT, LVL, __FUNCTION__, __LINE__, __VA_ARGS__); \
  }
#else
#define DBG(LVL,FMT,ARG...) \
  if (LVL <= debug_level) { \
    \
    fprintf(stderr, PROG_NAME"<%d>:%s:%d: " FMT, LVL, __FUNCTION__, __LINE__, ##ARG); \
  }
#endif
#endif

#ifdef _MSC_VER
#define CRIT(FMT, ...) { \
    fprintf(stderr, PROG_NAME " Critical:%s:%d: " FMT, __FUNCTION__, __LINE__, __VA_ARGS__); \
  }
#else
#define CRIT(FMT,ARG...) { \
    fprintf(stderr, PROG_NAME " Critical:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
  }
#endif

#ifdef _MSC_VER
#define VT_ERROR(FMT, ...) { \
    fprintf(stderr, PROG_NAME " ERROR:%s:%d: " FMT, __FUNCTION__, __LINE__, __VA_ARGS__); \
  }
#else
#define VT_ERROR(FMT,ARG...) { \
    fprintf(stderr, PROG_NAME " ERROR:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
  }
#endif

#ifdef _MSC_VER
#define WARN(FMT, ...) { \
    fprintf(stderr, PROG_NAME " Warning:%s:%d: " FMT, __FUNCTION__, __LINE__, __VA_ARGS__); \
  }
#else
#define WARN(FMT,ARG...) { \
    fprintf(stderr, PROG_NAME " Warning:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
  }
#endif

#ifdef _MSC_VER
#define INFO(FMT, ...) { \
    fprintf(stderr, PROG_NAME " Info:%s:%d: " FMT, __FUNCTION__, __LINE__, __VA_ARGS__); \
  }
#else
#define INFO(FMT,ARG...) { \
    fprintf(stderr, PROG_NAME " Info:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
  }
#endif

#ifdef _MSC_VER
#define VT_ERROR_FATAL(FMT, ...) { CRIT(FMT, __VA_ARGS__); BUG(); }
#else
#define VT_ERROR_FATAL(FMT,ARG...) { CRIT(FMT, ##ARG); BUG(); }
#endif

// lower level init goes first
#ifdef _MSC_VER

#define CCALL __cdecl
#pragma section(".CRT$XCU",read)
#define INITIALIZER(f) \
  static void __cdecl f(void); \
  __declspec(allocate(".CRT$XCU")) void(__cdecl*f##_)(void) = f; \
  static void __cdecl f(void)
#define likely(x)      x
#define unlikely(x)    x
#elif defined(__GNUC__)

#define CCALL
#define INITIALIZER(f) \
  static void f(void) __attribute__((constructor));\
  static void f(void)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#endif

/*
#define __init__(x)  __attribute__ ((constructor (x)))
#define __init __init__(999)

#define __exit__(x) __attribute__ ((destructor(x)))
#define __exit __exit__(999)


*/

#ifdef WINDOWS
#define strdup(x)  _strdup(x)
#ifdef _MSC_VER
#define snprintf(buff, sz, FMT, ...)  _snprintf_s(buff, sz, _TRUNCATE, FMT, __VA_ARGS__)
#else
#define snprintf(buff, sz, FMT, ARG...)  _snprintf_s(buff, sz, _TRUNCATE, FMT, ##ARG)
#endif
#endif

/* Force a compilation VT_ERROR if condition is true, but also produce a
   result (of value 0 and type size_t), so the expression can *be used
   e.g. in a structure initializer (or where-ever else comma expressions
   aren't permitted). */
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); }))

/* &a[0] degrades to a pointer: a different type from an array */
#define __must_be_array(a) BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), typeof(&a[0])))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))


#ifndef json_array_foreach
//  json_array_foreach() was added in Jansson 2.5 in Aug 2013
// This macro will make it work on jansson 2.2 and later
#define json_array_foreach(array, index, value) \
  for(index = 0; \
    index < json_array_size(array) && (value = json_array_get(array, index)); \
    index++)
#endif



#define DGB_LEVEL_MEM 8

#endif /* VT_COMMON_H */

