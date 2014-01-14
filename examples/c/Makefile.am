
LIBVTC_CFLAGS = -g3 -I../../lib -Wall
LIBVTC_LDLAGS = -L../../lib -lvtcapi ${JANSSON_LIBS} ${LIBNL_LIBS}

noinst_bin_PROGRAMS = scan
noinst_bindir = $(abs_top_builddir)/example_progs

scan_SOURCES = scan.c
scan_CFLAGS = $(AM_CFLAGS) $(LIBVTC_CFLAGS)
scan_LDFLAGS = $(LIBVTC_LDLAGS) 