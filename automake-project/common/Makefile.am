lib_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = add.cpp add.h
libcommon_ladir = $(includedir)
libcommon_la_HEADERS = add.h
libcommon_la_LDFLAGS = -version-info $(LIBCOMMON_SO_VERSION) \
					   -no-undefined 

if OS_WIN32
libcommon_la_SOURCES += 
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcommon-1.0.0.pc

