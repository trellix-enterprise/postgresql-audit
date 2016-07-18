#! /bin/sh

xargs rm -fr << \EOF
	Makefile.in
	aclocal.m4
	autom4te.cache/
	config.h.in
	config.h.in~
	config-aux/
	pcre/.deps/
	pcre/Makefile
	pcre/config.h
	pcre/config.log
	pcre/config.status
	pcre/libpcre.pc
	pcre/libpcre16.pc
	pcre/libpcre32.pc
	pcre/libpcrecpp.pc
	pcre/libpcreposix.pc
	pcre/libtool
	pcre/pcre-config
	pcre/pcre.h
	pcre/pcre_stringpiece.h
	pcre/pcrecpparg.h
	pcre/stamp-h1
	yajl/Makefile.in
	yajl/src/Makefile.in
EOF
