include $(top_srcdir)/aminclude.am

ACLOCAL_AMFLAGS = -I m4

OPT_DIRS =
if ENABLE_EXAMPLES
OPT_DIRS += examples
endif

SUBDIRS = . lib $(OPT_DIRS)


# ensure the distribution of the doxygen configuration file
EXTRA_DIST = Doxygen

