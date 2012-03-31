AM_CPPFLAGS = -DLOCALEDIR=\"$(localedir)\"
LDADD = $(LIBINTL)

bin_PROGRAMS = gopenvpn
if INSTALL_GOVPNSTART
	bin_PROGRAMS += gopenvpnstart
endif

gopenvpn_LDADD = $(GTK_LIBS)	\
	$(GLADE_LIBS)		\
	$(GNOME_KEYRING_LIBS)	\
	$(X11_LIBS)

AM_CFLAGS = -Wall -ansi -pedantic		\
	$(GLADE_CFLAGS)				\
	$(GNOME_KEYRING_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(X11_CFLAGS)				\
	-DPIXMAPS_DIR=\""$(datadir)/gopenvpn"\" \
	-DSYSCONF_DIR=\""$(sysconfdir)"\"	\
	-DLOCALSTATE_DIR=\""$(localstatedir)"\"	\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"	\
	-DGLADE_DIR=\""$(datadir)/gopenvpn"\"

gopenvpn_SOURCES = gopenvpn.c gopenvpn.h	\
	eggtrayicon.c eggtrayicon.h gettext.h

if INSTALL_GOVPNSTART
	gopenvpnstart_SOURCES = gopenvpnstart.c
endif

gladedir = $(datadir)/gopenvpn
glade_DATA = gopenvpn.glade
EXTRA_DIST = $(glade_DATA)
