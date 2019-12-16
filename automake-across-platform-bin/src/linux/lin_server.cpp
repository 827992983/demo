#include <stdio.h>  
#include <unistd.h>  
#include <stdlib.h>  
#include <sys/param.h>  
#include <sys/stat.h>  
#include <sys/types.h>  
#include <fcntl.h>  
#include <signal.h>

#include "../common/logger.h"

static void CreateDaemon() 
{  
	int pid, fd;  

	// create sub process
	if ((pid = fork()) == -1) exit(1);  
	if (pid != 0) exit(0);

	// sub process leave from parent process group
	if (setsid() == -1) exit(1);

	// create sub process, leave from terminal
	if ((pid = fork()) == -1) exit(1);  
	if (pid != 0) exit(0);

	// close process old file descriptor
	for (int i = 0; i < NOFILE; i++)  
		close(i);  

	// chown directory
	if (chdir("/") == -1) exit(1);  

	// reset file access permission
	if (umask(0) == -1) exit(1);  

	// close stdin/stdout/stderr
	if ((fd = open("/dev/null", O_RDWR)) == -1) exit(1);   
	dup2(fd, STDIN_FILENO);  
	dup2(fd, STDOUT_FILENO);  
	dup2(fd, STDERR_FILENO);  
	close(fd);  

	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) exit(1);  
}  

int LinuxDesktopHostServer(int argc, char *argv[])
{
	int ret = 0;
	
	// create daemon
	CreateDaemon();

/*
	// init server
	ret = InitServer();
	if(ret < 0)
	{
		return -1;
	}

	// connect vdagent server
	ConnectVdagentServer();

	// start server
	StartServer(); 
*/
	return 0;  
}  
