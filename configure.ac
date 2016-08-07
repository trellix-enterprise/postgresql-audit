#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(postgres-audit-plugin, [dev])
AC_CONFIG_AUX_DIR([config-aux])
AC_CANONICAL_TARGET

dnl AC_CONFIG_SRCDIR([src/audit_plugin.cc])
AC_CONFIG_HEADER([config.h])

AC_DEFUN([CHECK_DEBUG], [
	debug_default="no"
	AC_ARG_ENABLE(debug, [--enable-debug=[no/yes] turn on debugging
		[default=$debug_default]],, enable_debug=$debug_default)
	AC_MSG_CHECKING([whether to enable debugging])

	if test "$enable_debug" = "yes"
	then
		CPPFLAGS="$CPPFLAGS -g -D_DEBUG"
		AC_MSG_RESULT([yes])
	else
		CPPFLAGS="$CPPFLAGS -g -O2"
		AC_MSG_RESULT([no])
	fi

])

dnl Run tests using C++ compiler 
dnl AC_LANG(C++)

# initialize automake
AM_INIT_AUTOMAKE([1.8 foreign tar-ustar])


#check debug
CHECK_DEBUG

#yajl include dir
YAJL_INC=-I`cd yajl/include && pwd`
AC_SUBST(YAJL_INC)

#pcre
(cd pcre && CFLAGS=-fPIC ./configure --enable-utf --disable-cpp --disable-shared --enable-static )
if test $? -ne 0
then 
	AC_MSG_ERROR([Failed pcre configure])
fi


dnl AC_PROG_CC set CFLAGS=-g if CFLAGS was empty before. Reset to empty value
dnl when not building a debug version.
dnl if test "$ac_test_CFLAGS" != set -a "$enable_debug" = no; then
dnl  CFLAGS=
dnl fi
dnl AC_PROG_CXX set CXXFLAGS=-g if CXXFLAGS was empty before. Reset to empty
dnl value when not building a debug version.
dnl if test "$ac_test_CXXFLAGS" != set -a "$enable_debug" = no; then
dnl   CXXFLAGS=
dnl fi


#check for programs
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_CXX
AC_PROG_CPP

AC_PATH_PROG(MV, mv, mv)
AC_PATH_PROG(RM, rm, rm)
AC_PATH_PROG(CP, cp, cp)
AC_PATH_PROG(SED, sed, sed)
AC_PATH_PROG(CMP, cmp, cmp)
AC_PATH_PROG(CHMOD, chmod, chmod)
AC_PATH_PROG(HOSTNAME, hostname, hostname)
AC_PATH_PROG(DIFF, diff, diff)

#we can add the following flags for better error catching: -Werror -Wimplicit
CPPFLAGS="$CPPFLAGS -Werror -Wall"
CFLAGS="$CFLAGS -Wimplicit"

#make sure we have const
AC_C_CONST
AC_TYPE_SIZE_T

#version stuff
if test -z "$POSTGRESQL_AUDIT_PLUGIN_VERSION" ;then
	POSTGRESQL_AUDIT_PLUGIN_VERSION=1.0.0
fi
if test -z "$POSTGRESQL_AUDIT_PLUGIN_REVISION" ;then
	POSTGRESQL_AUDIT_PLUGIN_REVISION=99999
fi
if test -z "$POSTGRESQL_AUDIT_PLUGIN_SYMBOL_VERSION" ;then
        POSTGRESQL_AUDIT_PLUGIN_SYMBOL_VERSION=${POSTGRESQL_AUDIT_PLUGIN_VERSION//./_}_$POSTGRESQL_AUDIT_PLUGIN_REVISION
fi


AC_SUBST(POSTGRESQL_AUDIT_PLUGIN_VERSION)
AC_SUBST(POSTGRESQL_AUDIT_PLUGIN_REVISION)
echo "Version: $POSTGRESQL_AUDIT_PLUGIN_VERSION-$POSTGRESQL_AUDIT_PLUGIN_REVISION Symbol version: $POSTGRESQL_AUDIT_PLUGIN_SYMBOL_VERSION"
CPPFLAGS="$CPPFLAGS -DPOSTGRESQL_AUDIT_PLUGIN_VERSION='\"$POSTGRESQL_AUDIT_PLUGIN_VERSION\"'"
CPPFLAGS="$CPPFLAGS -DPOSTGRESQL_AUDIT_PLUGIN_REVISION='\"$POSTGRESQL_AUDIT_PLUGIN_REVISION\"'"
CPPFLAGS="$CPPFLAGS '-DPOSTGRESQL_AUDIT_PLUGIN_SYMBOL_VERSION()=extern const char audit_plugin_version_$POSTGRESQL_AUDIT_PLUGIN_SYMBOL_VERSION'"


#subst the relevant variables
AC_SUBST(CPPFLAGS)
AC_SUBST(CXXFLAGS)
AC_SUBST(CFLAGS)

AC_CONFIG_FILES([
		src/Makefile.pg
		yajl/Makefile
		yajl/src/Makefile
				])
AC_OUTPUT

AC_MSG_NOTICE([CPPFLAGS: $CPPFLAGS])
