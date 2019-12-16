bin_PROGRAMS = vd_host

vd_host_SOURCES = main.cpp common/base64.cpp common/base64.h \
					   common/cfg_op.cpp common/cfg_op.h \
					   common/cjson.cpp common/cjson.h \
					   common/logger.cpp common/logger.h \
					   common/utf8.cpp common/utf8.h \
					   common/list.h common/locker.h 

vd_host_LDFLAGS = -static
vd_host_CXXFLAGS = 
vd_host_LDADD =


if OS_WIN32
AM_CPPFLAGS = -DOLDMSVCRT	
vd_host_SOURCES += windows/win_common.cpp windows/win_common.h \
						windows/as_user.cpp windows/as_user.h \
						windows/win_server.cpp windows/win_server.h
vd_host_CXXFLAGS += $(AM_CXXFLAGS)
vd_host_LDFLAGS += $(AM_LDFLAGS) -Wl,--subsystem,windows
vd_host_LDADD += -lwtsapi32 -lgdi32 -lws2_32 -lnetapi32 -luser32 -lkernel32 
else
vd_host_SOURCES += linux/lin_server.cpp linux/lin_server.h
vd_host_CXXFLAGS += 
vd_host_LDADD += -lpthread -lm
endif


