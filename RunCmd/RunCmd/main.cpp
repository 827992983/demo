#include "stdafx.h"

#include <windows.h>
#include <stdio.h>
#include "RunCmd.h"

int main()
{
	char *cmd = "dir";
	char *output = new char[4096];
	memset(output, 0, 4096);
	int ret = RunCmd(cmd, 10, output);
	printf("ret=%d\n", ret);
	printf("%s\n", output);
	return 0;
}