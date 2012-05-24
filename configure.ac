#    gopenvpn - a GTK based GUI front-end for OpenVPN
#
#    Copyright (C) 2006-2012  Gary Grossman <gary@softwareasart.com>
#    Copyright (C) 2012-      David Sommerseth <dazo@users.sourceforge.net>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

AC_PREREQ([2.59])
AC_INIT([gopenvpn], [0.7], [gopenvpn-users@lists.sourceforge.net])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_GNU_GETTEXT_VERSION([0.18.1])
AM_GNU_GETTEXT([external])

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL

# Checks for libraries
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([socket strrchr])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h paths.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([socket strrchr])

# Checks for needed packages (pkg-config)
PKG_PROG_PKG_CONFIG
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

# Check for PolicyKit pkexec - can be overridden by --with-pkexec
AC_ARG_WITH([pkexec],
        AC_HELP_STRING([--with-pkexec=/path/to/pkexec], [Full path to PolicyKit pkexec]))
if test "x${with_pkexec}" = x; then
   # Auto-detect path if no explicit path was set
   AC_PATH_PROGS([PKEXEC_BINPATH], [pkexec],, [$PATH])
   if test -x "$PKEXEC_BINPATH"; then
      AC_DEFINE_UNQUOTED([USE_PKEXEC], [1], [Use pkexec for privileged operations])
      AC_DEFINE_UNQUOTED([PKEXEC_BINARY_PATH], ["$PKEXEC_BINPATH"], [Path to PolicyKit pkexec])
   else
      AC_MSG_WARN([PolicyKit pkexec was not found])
   fi
else
   if ! test "x${with_pkexec}" = xno; then
      AC_DEFINE_UNQUOTED([USE_PKEXEC], [1], [Use pkexec for privileged operations])
      AC_DEFINE_UNQUOTED([PKEXEC_BINARY_PATH], ["$with_pkexec"], [Path to PolicyKit pkexec])
   else
      AC_MSG_WARN([PolicyKit is not enabled])
   fi
fi
AM_CONDITIONAL([INSTALL_GOVPNSTART], [test ! -z $USE_PKEXEC])

# Check for gedit - can be overridden by --with-gedit
AC_ARG_WITH([gedit],
        AC_HELP_STRING([--with-gedit=/path/to/gedit], [Full path to gedit]))
if test "x${with_gedit}" = x; then
   # Auto-detect path if no explicit path was set
   AC_PATH_PROGS([GEDIT_BINPATH], [gedit],, [$PATH])
   if test -x "GEDIT_BINPATH"; then
      AC_MSG_ERROR([gedit was not found])
   fi
else
   if ! test "x${with_gedit}" = xno; then
      GEDIT_BINARY_PATH="$with_gedit"
   fi
fi
AC_DEFINE_UNQUOTED([GEDIT_BINARY_PATH], ["$GEDIT_BINPATH"], [Path to gedit])

# Check for openvpn - can be overridden by --with-openvpn
AC_ARG_WITH([openvpn],
        AC_HELP_STRING([--with-openvpn=/path/to/openvpn], [Full path to openvpn]))
if test "x${with_openvpn}" = x; then
   # Auto-detect path if no explicit path was set
   AC_PATH_PROGS([OPENVPN_BINPATH], [openvpn],, [$PATH])
   if test -x "OPENVPN_BINPATH"; then
      AC_MSG_ERROR([OpenVPN binary not found])
   fi
else
   if ! test "x${with_openvpn}" = xno; then
      OPENVPN_BINPATH="$with_openvpn"
   fi
fi
AC_DEFINE_UNQUOTED([OPENVPN_BINARY_PATH], ["$OPENVPN_BINPATH"], [Path to OpenVPN])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([src/gopenvpn.h])
AC_CONFIG_FILES([pixmaps/Makefile
                 po/Makefile.in
                 polkit/Makefile
                 src/Makefile
                 Makefile])
AC_OUTPUT
