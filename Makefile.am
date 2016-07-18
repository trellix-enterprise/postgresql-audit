## top-level Makefile.am

# This is a bit of a bastardization. We use the GNU Autotools to configure
# and build the libraries (pcre, yajl) but the plugin itself is
# built using the PostgreSQL build system.

clean-local:
	cd pcre && $(MAKE) $(AM_MAKEFLAGS) clean
	$(MAKE) -f $(srcdir)/Makefile.pg $(AM_MAKEFLAGS) clean

install:
	$(MAKE) -f Makefile.pg install

uninstall:
	$(MAKE) -f Makefile.pg uninstall


# Build in these directories:
SUBDIRS = yajl

# Distribute these directories:
DIST_SUBDIRS =  $(SUBDIRS)

bin_PROGRAMS = dummy

# pcre dependencies
$(top_srcdir)/pcre/libpcre.la:
	cd $(top_srcdir)/pcre && $(MAKE) $(AM_MAKEFLAGS) libpcre.la

isecg_audit.so: $(wildcard *.h *.cc)
	$(MAKE) -f $(srcdir)/Makefile.pg

dummy$(EXEEXT): $(top_srcdir)/pcre/libpcre.la isecg_audit.so
	$(CC) dummy.c -o $@
