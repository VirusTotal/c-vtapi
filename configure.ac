AC_INIT([VirusTotal API], [0.1], [karl.hiramoto@virustotaol.com], [c-vtapi])
AC_PREREQ(2.61)

AC_CONFIG_MACRO_DIR([m4])

dnl -Wall and -Werror here are NOT CFLAGS, they refer to automake warnings
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AM_PROG_AR
AC_PROG_LIBTOOL
AM_PROG_CC_C_O


######################################################################
# DOXYGEN SUPPORT
######################################################################


DX_INIT_DOXYGEN([$PACKAGE_NAME],[Doxyfile],doc)

DX_HTML_FEATURE(ON)
# DX_CHM_FEATURE(OFF)
# DX_CHI_FEATURE(OFF)
# DX_MAN_FEATURE(OFF)
# DX_RTF_FEATURE(OFF)
# DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(ON)
# DX_PS_FEATURE(OFF)


######################################################################

AC_CONFIG_HEADERS([c-vtapi_config.h])


CFLAGS="${CFLAGS} -Os -Wall -Werror -g3 "

AC_LANG([C])
# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string])

AC_CHECK_LIB([c], [fallocate],
	AC_DEFINE([HAVE_FALLOCATE], [1],[Has fallocate call]))

AC_ARG_WITH(jansson-include-dir,
	AS_HELP_STRING([--with-libjansson-include-dir=DIR],
	[location of libjansson headers])
	,,)

AC_ARG_WITH(jansson-lib-dir,
	AS_HELP_STRING([--with-libjansson-lib-dir=DIR],
		[location of libjansson library binary])
	,,)


if test "x$with_libjansson_include_dir" != "x" ; then
	JANSSONJANSSON_INCLUDE="-I$with_libjansson_include_dir"
else
	JANSSON_INCLUDE="-I/usr/include/libjansson/"
fi

if test "x$with_libjansson_lib_dir" != "x" ; then
	JANSSON_LDFLAGS="-L$with_libjansson_lib_dir -ljansson -lz"
else
	JANSSON_LDFLAGS=" -ljansson -lz"
fi

AC_SUBST(JANSSON_INCLUDE)
AC_SUBST(JANSSON_LDFLAGS)

AC_SEARCH_LIBS([json_object], [jansson],  [], [
  AC_MSG_ERROR([unable to find the jansson library])
])



AC_ARG_ENABLE(examples,
	AS_HELP_STRING([--enable-examples],
		[compile example programs]),
	AC_DEFINE([ENABLE_EXAMPLES], [1], [Define if we want example programs]),
	AC_DEFINE([DISABLE_EXAMPLES], [1], [Disable examples]),
	)

AC_SEARCH_LIBS([curl_global_init], [curl], [], [
  AC_MSG_ERROR([unable to find the curl_global_init() function])
])


AM_CONDITIONAL([ENABLE_EXAMPLES], [test "$enable_examples" == "yes"])

AC_CONFIG_FILES([
	Makefile
	Doxyfile
	lib/Makefile
	examples/Makefile
	examples/c/Makefile
	])
#ui/Makefile

AC_OUTPUT
