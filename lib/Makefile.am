SUBDIRS = .

# CURRENT_USER=$(shell whoami)
# CURRENT_HOST=$(shell hostname)


lib_LTLIBRARIES = libvtcapi.la

#include_HEADERS = 

libvtcapi_la_CFLAGS  = -g3 -Wall -Werror 
libvtcapi_la_SOURCES = VtObject.c \
	VtApiPage.c \
	VtComments.c \
	VtDebug.c \
	VtDomain.c \
	VtFileScan.c \
	VtFileDist.c \
	VtIpAddr.c \
	VtResponse.c \
	VtUrl.c \
	VtUrlDist.c

libvtcapi_la_LDFLAGS = -version-info 1  -ljansson

