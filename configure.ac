AC_INIT(gopenvpn, 0.1)
AC_CONFIG_SRCDIR(src/gopenvpn.c)
AC_PREREQ(2.57)
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

AC_GNU_SOURCE

#
# Checks for programs.
#
AC_PROG_CC
AC_STDC_HEADERS
AC_PROG_INSTALL

#
# Checks for libraries.
#

#
# Checks for header files.
#
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_C_CONST
AC_TYPE_PID_T

#
# Checks for library functions.
#
AC_FUNC_FORK
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([socket strrchr])

# Make sure we have an actual value for $prefix
myprefix=$prefix
test x$myprefix = xNONE && myprefix=$ac_default_prefix

# openvpn binary path
AC_ARG_WITH(openvpn, AC_HELP_STRING([--with-openvpn=/path/to/openvpn], [path to openvpn])) 
if test "x${with_openvpn}" = x; then
  AC_PATH_PROG(OPENVPN_BINARY_PATH, openvpn, [], $PATH:/sbin:/usr/sbin)
  if ! test -x "$OPENVPN_BINARY_PATH"; then
	AC_MSG_ERROR(openvpn was not installed)
  fi
else
  OPENVPN_BINARY_PATH="$with_openvpn"
fi
AC_DEFINE_UNQUOTED(OPENVPN_BINARY_PATH, "$OPENVPN_BINARY_PATH", [Define to path of openvpn binary])
AC_SUBST(OPENVPN_BINARY_PATH)

# gksu binary path
AC_ARG_WITH(gksu, AC_HELP_STRING([--with-gksu=/path/to/gksu], [path to gksu])) 
USE_GKSU=0
if test "x${with_gksu}" = x; then
  AC_PATH_PROG(GKSU_BINARY_PATH, gksu, [], $PATH:/usr/bin)
  if ! test -x "$GKSU_BINARY_PATH"; then
	AC_MSG_ERROR(gksu was not installed)
  fi
  USE_GKSU=1
else
  if test "x${with_gksu}" = xno; then
    USE_GKSU = 0
  else
    GKSU_BINARY_PATH="$with_gksu"
    USE_GKSU=1
  fi
fi
AC_DEFINE_UNQUOTED(GKSU_BINARY_PATH, "$GKSU_BINARY_PATH", [Define to path of gksu binary])
AC_SUBST(GKSU_BINARY_PATH)
AC_DEFINE_UNQUOTED(USE_GKSU, $USE_GKSU, [Indicates whether gksu is used])
AC_SUBST(USE_GSKU)

AC_DEFINE_UNQUOTED(GOPENVPNSTART_BINARY_PATH, "$myprefix/bin/gopenvpnstart", [Path of gopenvpnstart binary])
AC_SUBST(GOPENVPNSTART_BINARY_PATH)

# gedit binary path
AC_ARG_WITH(gedit, AC_HELP_STRING([--with-gedit=/path/to/gedit], [path to gedit])) 
if test "x${with_gedit}" = x; then
  AC_PATH_PROG(GEDIT_BINARY_PATH, gedit, [], $PATH:/usr/bin)
  if ! test -x "$GEDIT_BINARY_PATH"; then
	AC_MSG_ERROR(gedit was not installed)
  fi
else
  GEDIT_BINARY_PATH="$with_gedit"
fi
AC_DEFINE_UNQUOTED(GEDIT_BINARY_PATH, "$GEDIT_BINARY_PATH", [Define to path of gedit binary])
AC_SUBST(GEDIT_BINARY_PATH)

#
# translation support
#
GETTEXT_PACKAGE=gopenvpn
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])
ALL_LINGUAS="fr"
AC_PROG_INTLTOOL([0.23])
AM_GLIB_GNU_GETTEXT

PKG_CHECK_MODULES(GTK, gtk+-2.0)
AC_SUBST(GTK_CFLAGS)
AC_SUBST(GTK_LIBS)

PKG_CHECK_MODULES(GLADE, libglade-2.0)
AC_SUBST(GLADE_CFLAGS)
AC_SUBST(GLADE_LIBS)

PKG_CHECK_MODULES(GNOME_KEYRING, gnome-keyring-1)
AC_SUBST(GNOME_KEYRING_CFLAGS)
AC_SUBST(GNOME_KEYRING_LIBS)

AC_OUTPUT([Makefile
           pixmaps/Makefile
           src/Makefile
           po/Makefile.in])

