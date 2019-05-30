lib_LTLIBRARIES = libprotocol.la

libprotocol_la_SOURCES = add_ext.cpp add_ext.h
libprotocol_ladir = $(includedir)
libprotocol_la_HEADERS = add_ext.h
libprotocol_la_CFLAGS = $(LIBUSB_CFLAGS) -I$(top_srcdir)/common
libprotocol_la_LIBADD = $(LIBUSB_LIBS) \
                            $(top_builddir)/common/libcommon.la
libprotocol_la_LDFLAGS = -version-info $(LIBPROTOCOL_SO_VERSION) \
						 -no-undefined

if OS_WIN32
libprotocol_la_SOURCES += 
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libprotocol-1.0.0.pc

