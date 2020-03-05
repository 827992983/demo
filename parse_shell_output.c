#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int run_cmd(char* cmdstring, char* buf, int len)
{
	int   fd[2];
	pid_t pid;
	int   n, count; 
	memset(buf, 0, len);
	if (pipe(fd) < 0)
		return -1;
	if ((pid = fork()) < 0)
		return -1;
	else if (pid > 0)     
	{
		close(fd[1]);     
		count = 0;
		while ((n = read(fd[0], buf + count, len)) > 0 && count > len)
			count += n;
		close(fd[0]);
		if (waitpid(pid, NULL, 0) > 0)
			return -1;
	}
	else                  
	{
		close(fd[0]);     
		if (fd[1] != STDOUT_FILENO)
		{
			if (dup2(fd[1], STDOUT_FILENO) != STDOUT_FILENO)
			{
				return -1;
			}
			close(fd[1]);
		} 
		if (execl("/bin/sh", "sh", "-c", cmdstring, (char*)0) == -1)
			return -1;
	} 
	return 0;
}

int main(const int argc, const char** argv)
{
	char *cmd = "ls -l|grep li";
	char *output = (char *)malloc(1024);
	memset(output, 0, 1024);
	run_cmd(cmd, output, 1024);
	printf("--------\n%s\n-------\n", output);
	return 0;
}
