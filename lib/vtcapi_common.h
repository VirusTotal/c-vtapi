/*
Copyright (C) <2013> VirusTotal.
*/

#ifndef VT_COMMON_H
#define VT_COMMON_H

#ifdef HAVE_CONFIG_H
#include "c-vtapi_config.h"
#endif

#include <stdio.h>
#include <assert.h>
#include <syslog.h>
#include <pthread.h>

#define BUG()                \
	do {                 \
		fprintf(stderr, "BUG: %s:%d\n",  \
		__FILE__, __LINE__);         \
		fflush(stderr); \
		fflush(stdout); \
		assert(0);	\
	} while (0)
// 
/* program name is package name from config.h*/
#define PROG_NAME PACKAGE


#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define PRINT(FMT,ARG...) printf(PROG_NAME": " FMT, ##ARG); \

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
#define DBG(LVL,FMT,ARG...) \
	if (LVL <= debug_level) {\
		fprintf(stderr, PROG_NAME"<" #LVL ">:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	}
#endif

#define CRIT(FMT,ARG...) { \
fprintf(stderr, PROG_NAME " Critical:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
syslog(LOG_CRIT, PROG_NAME " Critical:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
}

#define ERROR(FMT,ARG...) { \
	fprintf(stderr, PROG_NAME " Error:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	syslog(LOG_ERR, PROG_NAME " Error:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	}

#define WARN(FMT,ARG...) { \
	fprintf(stderr, PROG_NAME " Warning:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	syslog(LOG_WARNING, PROG_NAME " Warning:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	}

#define INFO(FMT,ARG...) { \
	fprintf(stderr, PROG_NAME " Info:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	syslog(LOG_INFO, PROG_NAME " Info:%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \
}
	
	
#define ERROR_FATAL(FMT,ARG...) { CRIT(FMT, ##ARG); BUG(); }


// lower level init goes first
#define __init__(x)  __attribute__ ((constructor (x)))
#define __init __init__(999)

#define __exit__(x) __attribute__ ((destructor(x)))
#define __exit __exit__(999)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)


/* Force a compilation error if condition is true, but also produce a 
   result (of value 0 and type size_t), so the expression can *be used 
   e.g. in a structure initializer (or where-ever else comma expressions 
   aren't permitted). */ 
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); })) 

/* &a[0] degrades to a pointer: a different type from an array */ 
#define __must_be_array(a) BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), typeof(&a[0]))) 

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))


#define DGB_LEVEL_MEM 8

#endif /* VT_COMMON_H */

