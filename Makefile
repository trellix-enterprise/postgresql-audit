all: pcre/libpcre.la yajl-build src/audit.so 

# pcre dependencies
pcre/libpcre.la:
	cd pcre && $(MAKE) libpcre.la

# yajl
yajl-build:
	cd yajl && $(MAKE)

src/audit.so: $(wildcard include/*.h src/*.cc)
	cd src && $(MAKE) -f Makefile.pg

clean:
	cd pcre && $(MAKE) clean
	cd yajl && $(MAKE) clean
	cd src && $(MAKE) -f Makefile.pg clean

distclean: clean
	./Cleanup.sh

install: all
	cd src && $(MAKE) -f Makefile.pg install

uninstall: all
	cd src && $(MAKE) -f Makefile.pg uninstall
