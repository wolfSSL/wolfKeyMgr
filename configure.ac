# wolf Key Manager
# Copyright (C) 2021 wolfSSL Inc.
# All rights reserved.
#

AC_PREREQ(2.59)

AC_INIT([wolfKeyManager],[0.3],[http://www.wolfssl.com])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADERS([wolfkeymgr/config.h])
AC_CONFIG_MACRO_DIR(m4)

# The following sets CFLAGS to empty if unset on command line.  We do not
# want the default "-g -O2" that AC_PROG_CC sets automatically.
: ${CFLAGS=""}

AM_INIT_AUTOMAKE(subdir-objects foreign)

# Install path
#AC_PREFIX_DEFAULT(/usr/local/wolfssl)
AC_ARG_PROGRAM
AC_DEFUN([PROTECT_AC_USE_SYSTEM_EXTENSIONS],
         [AX_SAVE_FLAGS
          AC_LANG_PUSH([C])
          AC_USE_SYSTEM_EXTENSIONS
          AC_LANG_POP([C])
          AX_RESTORE_FLAGS
          ])
#PROTECT_AC_USE_SYSTEM_EXTENSIONS

AX_TLS([AM_CFLAGS="$AM_CFLAGS -DHAVE_THREAD_LS"],
        AC_MSG_ERROR([Need compiler support for thread local storage. If on OS X try using CC=clang]))

# Make sure configure doesn't add to CFLAGS
CFLAGS="$CFLAGS $C_EXTRA_FLAGS"

# silent
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_INSTALL

# Setup visibility
gl_VISIBILITY
AS_IF([ test -n "$CFLAG_VISIBILITY" ], [
       AM_CFLAGS="$AM_CPPFLAGS $CFLAG_VISIBILITY"
       ])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_SIZEOF(long long, 8)
AC_CHECK_SIZEOF(long, 4)

# Check headers/libs
AC_CHECK_FUNCS([gethostbyname])
AC_CHECK_FUNCS([getaddrinfo])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([socket])
AC_CHECK_LIB(network,socket)

# Requirements
PANDORA_REQUIRE_PTHREAD
PANDORA_REQUIRE_LIBEVENT
WOLF_REQUIRE_LIBWOLFSSL

LT_PREREQ([2.2])
LT_INIT([disable-static win32-dll])

# Shared library versioning
WOLFKM_LIBRARY_VERSION=3:0:0
#                      | | |
#               +------+ | +---+
#               |        |     |
#             current:revision:age
#               |        |     |
#               |        |     +- increment if interfaces have been added
#               |        |        set to zero if interfaces have been removed
#               |        |        or changed
#               |        +- increment if source code has changed
#               |           set to zero if current is incremented
#               +- increment if interfaces have been added, removed or changed
AC_SUBST([WOLFKM_LIBRARY_VERSION])

# compiler options
CFLAGS="$CFLAGS -Wall"
CFLAGS_DEBUG="-g"
CFLAGS_OPTIMIZE="-O2"

# Checks for typedefs, structures, and compiler characteristics.
if test "$ac_cv_sizeof_long" = "8"; then
    CFLAGS="$CFLAGS -DSIZEOF_LONG=8"
else
    if test "$ac_cv_sizeof_long_long" = "8"; then
        CFLAGS="$CFLAGS -DSIZEOF_LONG_LONG=8"
    fi
fi


# pthread flags
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
LIBS="$LIBS $PTHREAD_LIBS"

# DEBUG
AX_DEBUG
AS_IF([test "$ax_enable_debug" = "yes"],
      [CFLAGS="$CFLAGS_DEBUG $CFLAGS"],
      [CFLAGS="$CFLAGS_OPTIMIZE -DNDEBUG $CFLAGS"])


# system depedent stuff
case "$host_os" in
  *darwin*)
LDFLAGS="$LDFLAGS"
  ;;
esac

# Checks for library functions.
LIB_SOCKET_NSL


# ETSI Service
AC_ARG_ENABLE([etsisvc],
    [AS_HELP_STRING([--enable-etsisvc],[Enable the ETSI key service (default: enabled)])],
    [ ENABLED_ETSI_SERVICE=$enableval ],
    [ ENABLED_ETSI_SERVICE=yes ]
    )

if test "x$ENABLED_ETSI_SERVICE" = "xyes"
then
    CFLAGS="$CFLAGS -DWOLFKM_ETSI_SERVICE"
fi



# The following AM_CONDITIONAL statements set flags for use in the Makefiles.
# Some of these affect build targets and objects, some trigger different
# test scripts for make check.
AM_CONDITIONAL([BUILD_ETSI_SERVICE],[test "x$ENABLED_ETSI_SERVICE" = "xyes"])


# FINAL
AC_CONFIG_FILES([Makefile wolfkeymgr/options.h wolfkeymgr/version.h])

AX_AM_JOBSERVER([yes])

AC_OUTPUT()


# force make clean
echo "---"
echo "Running make clean..."
make clean >/dev/null 2>&1
echo


# generate user options header
echo "---"
echo "Generating user options header..."

OPTION_FILE="wolfkeymgr/options.h"
rm -f $OPTION_FILE

echo "/* wolf key manager options.h" > $OPTION_FILE
echo " * generated from configure options" >> $OPTION_FILE
echo " *" >> $OPTION_FILE
echo " * Copyright (C) 2006-2021 wolfSSL Inc." >> $OPTION_FILE
echo " *" >> $OPTION_FILE
echo " */" >> $OPTION_FILE

echo "" >> $OPTION_FILE
echo "#ifndef WOLFKM_OPTIONS_H" >> $OPTION_FILE
echo "#define WOLFKM_OPTIONS_H" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "#ifdef __cplusplus" >> $OPTION_FILE
echo "extern \"C\" {" >> $OPTION_FILE
echo "#endif" >> $OPTION_FILE
echo "" >> $OPTION_FILE

for option in $CPPFLAGS $AM_CPPFLAGS $CFLAGS $AM_CFLAGS; do
    defonly=`echo $option | sed 's/^-D//'`
    if test "$defonly" != "$option"
    then
        noequalsign=`echo $defonly | sed 's/=/ /'`
        if test "$noequalsign" = "NDEBUG" || test "$noequalsign" = "DEBUG"
        then
            echo "not outputting (N)DEBUG to $OPTION_FILE"
            continue
        fi

        # allow user to ignore system options
        ignoresys=$(echo "$noequalsign" | grep '^_.*')
        if test -n "$ignoresys"
        then
            echo "#ifndef WOLFKM_OPTIONS_IGNORE_SYS" >> $OPTION_FILE
        fi

        noarg=`echo $defonly | sed 's/=.*//'`
        echo "#undef  $noarg" >> $OPTION_FILE
        echo "#define $noequalsign" >> $OPTION_FILE

        if test -n "$ignoresys"
        then
            echo "#endif" >> $OPTION_FILE
        fi

        echo "" >> $OPTION_FILE
    else
        echo "option w/o begin -D is $option, not saving to $OPTION_FILE"
    fi
done

echo "" >> $OPTION_FILE
echo "#ifdef __cplusplus" >> $OPTION_FILE
echo "}" >> $OPTION_FILE
echo "#endif" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "#endif /* WOLFKM_OPTIONS_H */" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo


# output config summary
echo "---"
echo "Configuration summary for $PACKAGE_NAME version $VERSION"
echo ""
echo "   * Installation prefix:       $prefix"
echo "   * System type:               $host_vendor-$host_os"
echo "   * Host CPU:                  $host_cpu"
echo "   * C Compiler:                $CC_VERSION"
echo "   * C Flags:                   $CFLAGS"
echo "   * CPP Flags:                 $CPPFLAGS"
echo "   * LIB Flags:                 $LIB"
echo "   * Debug enabled:             $ax_enable_debug"

echo "   * ETSI Service               $ENABLED_ETSI_SERVICE"
