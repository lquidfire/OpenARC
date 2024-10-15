# Copyright (c) 2010-2014, 2016, 2017, The Trusted Domain Project.
# All rights reserved.

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = contrib . test
dist_doc_DATA = LICENSE LICENSE.Sendmail README.md RELEASE_NOTES
dist_noinst_SCRIPTS = libtool

DISTCLEANFILES = openarc-@VERSION@.tar.gz libopenarc/symbols.map *.gcno *.gcda

# TODO: get configure.ac to generate --enable-{feature} for all
# non-experimental features and substitute it here e.g  @SUPPORTED_FEATURES@.
# Perhaps all features would enable a more comprehensive test coverage map
# though.
DISTCHECK_CONFIGURE_FLAGS=--with-openssl=/usr/local

if DEBUG
AM_CFLAGS = -g
endif

LDADD = libopenarc/libopenarc.la

lib_LTLIBRARIES = libopenarc/libopenarc.la
libopenarc_libopenarc_la_SOURCES = \
	libopenarc/base64.c \
	libopenarc/base64.h \
	libopenarc/arc.c \
	libopenarc/arc.h \
	libopenarc/arc-canon.c \
	libopenarc/arc-canon.h \
	libopenarc/arc-dns.c \
	libopenarc/arc-dns.h \
	libopenarc/arc-internal.h \
	libopenarc/arc-keys.c \
	libopenarc/arc-keys.h \
	libopenarc/arc-mailparse.c \
	libopenarc/arc-mailparse.h \
	libopenarc/arc-tables.c \
	libopenarc/arc-tables.h \
	libopenarc/arc-types.h \
	libopenarc/arc-util.c \
	libopenarc/arc-util.h \
	util/arc-dstring.c \
	util/arc-dstring.h
libopenarc_libopenarc_la_CPPFLAGS = -I$(srcdir)/util $(LIBCRYPTO_CPPFLAGS)
libopenarc_libopenarc_la_CFLAGS = $(LIBCRYPTO_INCDIRS) $(LIBOPENARC_INC)
libopenarc_libopenarc_la_LDFLAGS = -no-undefined  $(LIBCRYPTO_LIBDIRS) -version-info $(LIBOPENARC_VERSION_INFO)
libopenarc_libopenarc_la_LIBADD = $(LIBOPENARC_LIBS) $(LIBCRYPTO_LDADD)
if !ALL_SYMBOLS
libopenarc_libopenarc_la_DEPENDENCIES = libopenarc/symbols.map
libopenarc_libopenarc_la_LDFLAGS += -export-symbols libopenarc/symbols.map
endif
if RPATH
libopenarc_libopenarc_la_LDFLAGS += -rpath $(libdir)
endif
libopenarc_libopenarc_includedir = $(includedir)/openarc
libopenarc_libopenarc_include_HEADERS = libopenarc/arc.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libopenarc/openarc.pc

libopenarc/symbols.map: $(libopenarc_libopenarc_include_HEADERS)
	grep '^extern' $? | \
		awk '{ for (c = 1; c <= NF; c++) if ($$c ~ /arc_/) { print $$c; break; } }' | \
		sed -e s/\[\*\;\]//g -e s/\[\\\[\\\]\]//g -e s/\(.*// | \
		sort -u -o $@

if BUILD_FILTER
dist_doc_DATA += openarc/openarc.conf.sample
man_MANS = openarc/openarc.conf.5 openarc/openarc.8
sbin_PROGRAMS = openarc/openarc

openarc_openarc_SOURCES = \
	openarc/config.c \
	openarc/config.h \
	openarc/openarc.c \
	openarc/openarc.h \
	openarc/openarc-ar.c \
	openarc/openarc-ar.h \
	openarc/openarc-config.h \
	openarc/openarc-crypto.c \
	openarc/openarc-crypto.h \
	openarc/openarc-test.c \
	openarc/openarc-test.h \
	openarc/util.c \
	openarc/util.h \
	util/arc-dstring.c \
	util/arc-dstring.h
openarc_openarc_CC = $(PTHREAD_CC)
openarc_openarc_CFLAGS = $(PTHREAD_CFLAGS) $(LIBCRYPTO_CFLAGS)
openarc_openarc_CPPFLAGS = -I$(srcdir)/libopenarc -I$(srcdir)/util $(LIBCRYPTO_CPPFLAGS) $(LIBMILTER_INCDIRS) $(LIBJANSSON_CPPFLAGS)
openarc_openarc_LDFLAGS = $(LIBCRYPTO_LIBDIRS) $(LIBMILTER_LIBDIRS) $(PTHREAD_CFLAGS) $(LIBJANSSON_LDFLAGS)
openarc_openarc_LDADD = libopenarc/libopenarc.la $(LIBMILTER_LIBS) $(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) $(LIBJANSSON_LIBS) $(LIBRESOLV)
endif

$(DIST_ARCHIVES): distcheck

$(DIST_ARCHIVES).md5: $(DIST_ARCHIVES)
	md5 $? > $@ || md5sum $? > $@

$(DIST_ARCHIVES).sha1: $(DIST_ARCHIVES)
	sha1 $? > $@ || sha1sum $? > $@

$(DIST_ARCHIVES).asc: $(DIST_ARCHIVES)
	gpg -a -u security@trusteddomain.org --detach-sign $?

push: $(DIST_ARCHIVES) $(DIST_ARCHIVES).sha1 $(DIST_ARCHIVES).md5 $(DIST_ARCHIVES).asc
	@echo "Are you sure you want to tag and release $(DIST_ARCHIVES)? (y/n)"
	@read confirm && [ $$confirm = 'y' ]
	git tag rel-openarc-`echo $(VERSION) | sed 's/\./-/g'`
	git push --tags

dist-hook:
	[ -f $(distdir)/libopenarc/arc.h ] && rm -f $(distdir)/libopenarc/arc.h
	sed -e '/OPENARC_LIB_VERSION/s/0x[0-9]*/0x@HEX_VERSION@/' < $(srcdir)/libopenarc/arc.h > $(distdir)/libopenarc/arc.h
	echo "looking to see if @VERSION@ is in the RELEASE_NOTES"
	fgrep @VERSION@ $(srcdir)/RELEASE_NOTES
	sed -e 's|\(@VERSION@[ \t]*\)[0-9?]\{4\}\(/[0-9?]\{2\}\)\{2\}|\1'`date +%Y/%m/%d`'|' < $(srcdir)/RELEASE_NOTES > $(distdir)/RELEASE_NOTES

rpm: dist-gzip
	rpmbuild -ta $(distdir).tar.gz

.PHONY: push
