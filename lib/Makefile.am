SUBDIRS = .

# CURRENT_USER=$(shell whoami)
# CURRENT_HOST=$(shell hostname)


lib_LTLIBRARIES = libcvtapi.la

include_HEADERS = VtApiPage.h \
	VtComments.h \
	VtDomain.h \
	VtFile.h \
	VtFileDist.h \
	VtIpAddr.h \
	VtResponse.h \
	VtUrl.h \
	VtUrlDist.h

libcvtapi_la_CFLAGS  = -g3 -Wall -Werror
libcvtapi_la_SOURCES = VtObject.c \
	VtApiPage.c \
	VtComments.c \
	VtDebug.c \
	VtDomain.c \
	VtFile.c \
	VtFileDist.c \
	VtIpAddr.c \
	VtResponse.c \
	VtUrl.c \
	VtUrlDist.c

libcvtapi_la_LDFLAGS = -version-info 1  -ljansson

