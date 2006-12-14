NULL=

ubindir = ${prefix}/bin

bin_PROGRAMS = gopenvpn gopenvpnstart

gopenvpn_LDADD = $(GTK_LIBS)				\
	$(GLADE_LIBS)							\
	$(GNOME_KEYRING_LIBS)					\
	$(NULL)

AM_CFLAGS = -Wall -ansi -pedantic	\
	$(GLADE_CFLAGS)							\
	$(GNOME_KEYRING_CFLAGS)					\
	$(GTK_CFLAGS)							\
	-DPIXMAPS_DIR=\""$(datadir)/gopenvpn"\" \
	-DSYSCONF_DIR=\""$(sysconfdir)"\"		\
	-DLOCALSTATE_DIR=\""$(localstatedir)"\"	\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"	\
	-DGLADE_DIR=\""$(datadir)/gopenvpn"\"	\
	$(NULL)

gopenvpn_SOURCES = gopenvpn.c				\
	eggtrayicon.c							\
	$(NULL)

gopenvpnstart_SOURCES = gopenvpnstart.c		\
	$(NULL)

gladedir = $(datadir)/gopenvpn
glade_DATA = gopenvpn.glade
EXTRA_DIST = $(glade_DATA)

install-am: all-am
	$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am
	chmod -f 4755 $(DESTDIR)$(ubindir)/gopenvpnstart
