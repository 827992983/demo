#include <stdio.h>

#include "common/vd_global.h"

#ifdef _WIN32
#include <windows.h>
#include "windows/win_server.h"
#else
#include "linux/lin_server.h"
#endif

#include "common/logger.h"

int main(int argc, char *argv[])
{
	printf("Started\n");
	log_init(VD_HOST_LOG_FILE);
	LOG_DEBUG("vd_host Started!");
#ifdef _WIN32
	printf("Windows!\n");
	WindowsDesktopHostServer(argc, argv);
#else
	printf("Linux!\n");
	LinuxDesktopHostServer(argc, argv);
#endif
	LOG_DEBUG("vd_host Stop!");
	log_cleanup();
    return 0;
}

