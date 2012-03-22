AC_INIT(gopenvpn, 0.6)
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

# pkexec binary path
AC_ARG_WITH(pkexec, AC_HELP_STRING([--with-pkexec=/path/to/pkexec], [path to PolicyKit pkexec]))
if test "x${with_pkexec}" = x; then
  AC_PATH_PROG(PKEXEC_BINARY_PATH, pkexec, [], $PATH:/usr/bin)
  if ! test -x "$PKEXEC_BINARY_PATH"; then
	AC_MSG_ERROR(PolicyKit pkexec was not installed)
  fi
else
  if test "x${with_pkexec}" = xno; then
    USE_PKEXEC = 0
  else
    PKEXEC_BINARY_PATH="$with_pkexec"
  fi
fi
AC_DEFINE_UNQUOTED(PKEXEC_BINARY_PATH, "$PKEXEC_BINARY_PATH", [Define to path of PolicyKit pkexec binary])
AC_SUBST(PKEXEC_BINARY_PATH)

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

PKG_CHECK_MODULES(X11, x11)
AC_SUBST(X11_CFLAGS)
AC_SUBST(X11_LIBS)

PKG_CHECK_MODULES(POLKIT, polkit-gobject-1 >= 0.96)

AC_OUTPUT([Makefile
           pixmaps/Makefile
	   polkit/Makefile
           src/Makefile
           po/Makefile.in])

