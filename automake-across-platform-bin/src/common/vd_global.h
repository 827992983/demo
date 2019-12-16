#ifndef VD_GLOBAL_H
#define VD_GLOBAL_H

#include <stdio.h>

#define VD_DEBUG 1

#ifdef _WIN32
#define VD_HOST_CONFIG_FILE "C:\\Windows\\Temp\\QingCloud\\vd_host.cfg"
#define VD_HOST_LOG_FILE "C:\\Windows\\Temp\\QingCloud\\logs\\vd_host.log"
#else
#define VD_HOST_CONFIG_FILE "/etc/qing-cloud/vd_host.conf"
#define VD_HOST_LOG_FILE "/tmp/.QingCloud/logs/vd_host.log"
#endif

#endif
