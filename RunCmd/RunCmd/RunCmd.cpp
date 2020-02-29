// RunCmd.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include <windows.h> 
#include <stdio.h> 
#include <strsafe.h>
#include <time.h>

#define RET_TIME_OUT -1

static HANDLE g_hChildStd_IN_Rd = NULL;
static HANDLE g_hChildStd_IN_Wr = NULL;
static HANDLE g_hChildStd_OUT_Rd = NULL;
static HANDLE g_hChildStd_OUT_Wr = NULL;

static void ReadFromPipe(char *output)
{
	DWORD dwRead;
	BOOL bSuccess = FALSE;
	char chBuf[4096];

	for (;;) {
		memset(chBuf, 0, 4096);
		bSuccess = ReadFile(g_hChildStd_OUT_Rd, chBuf, sizeof(chBuf) - 1, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) break;

		chBuf[dwRead] = 0;
		memcpy(output, chBuf, dwRead);
	}

	return;
}

static BOOL CreateChildProcess(char *cmdline, PROCESS_INFORMATION *pi, STARTUPINFOA *si)
{
	BOOL bSuccess = FALSE;
	char _cmd[4096];

	ZeroMemory(pi, sizeof(PROCESS_INFORMATION));

	ZeroMemory(si, sizeof(STARTUPINFO));
	si->cb = sizeof(STARTUPINFO);
	si->hStdError = g_hChildStd_OUT_Wr;
	si->hStdOutput = g_hChildStd_OUT_Wr;
	si->hStdInput = g_hChildStd_IN_Rd;
	si->dwFlags |= STARTF_USESTDHANDLES;

	// add <NUL to prevent hang
	sprintf(_cmd, "cmd.exe /c \"%s <NUL\"", cmdline);
	bSuccess = CreateProcessA(NULL,
		_cmd,          // command line 
		NULL,          // process security attributes 
		NULL,          // primary thread security attributes 
		TRUE,          // handles are inherited 
		0,             // creation flags 
		NULL,          // use parent's environment 
		NULL,          // use parent's current directory 
		si,            // STARTUPINFO pointer 
		pi);           // receives PROCESS_INFORMATION 

	return bSuccess;
}

static BOOL KillChildProcess(PROCESS_INFORMATION * pi, DWORD exit_code)
{
	BOOL bSuccess = FALSE;
	DWORD pid = pi->dwProcessId;

	HANDLE hprocess = OpenProcess(PROCESS_TERMINATE, false, pid);
	if (hprocess == NULL) {
		printf("error open process");
		return FALSE;
	}

	bSuccess = TerminateProcess(hprocess, exit_code);
	CloseHandle(hprocess);

	printf("terminate process: %d", bSuccess);
	return bSuccess;
}

int RunCmd(char *cmdline, int timeout, char *output)
{
	int ret_code = -1;
	SECURITY_ATTRIBUTES saAttr;

	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	g_hChildStd_IN_Rd = NULL;
	g_hChildStd_IN_Wr = NULL;
	g_hChildStd_OUT_Rd = NULL;
	g_hChildStd_OUT_Wr = NULL;

	if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0)) {
		printf("error creating child pipe");
		goto _EXIT;
	}

	if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
		printf("error setting handle information");
		goto _EXIT;
	}

	if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) {
		printf("error creating child pipe");
		goto _EXIT;
	}

	if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) {
		printf("error setting handle information");
		goto _EXIT;
	}

	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	if (!CreateChildProcess(cmdline, &pi, &si)) {
		printf("error creating child process");
		goto _EXIT;
	}

	// don't need to write to child, close it otherwise reading will hang
	CloseHandle(g_hChildStd_OUT_Wr);
	g_hChildStd_OUT_Wr = NULL;

	time_t now = time(0);
	while (1) {
		// time out
		if (timeout > 0) {
			if (time(NULL) >= now + timeout) {
				ret_code = RET_TIME_OUT;
				KillChildProcess(&pi, RET_TIME_OUT);
				break;
			}
		}

		// must wait until child exists to prevent zombie
		WaitForSingleObject(pi.hProcess, 100);

		DWORD exit_code;
		DWORD rc = GetExitCodeProcess(pi.hProcess, &exit_code);
		if (rc == FALSE) {
			printf("waitpid");
			break;
		}
		if (exit_code != STILL_ACTIVE) {
			// normal exit
			ret_code = exit_code;
			break;
		}

		// child still exists, wait...
		Sleep(50);
	}

	printf("-- request returns: [%d]\n", ret_code);

	// Read from pipe that is the standard output for child process. 
	if (ret_code != RET_TIME_OUT) {
		ReadFromPipe(output);
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
_EXIT:
	if (g_hChildStd_IN_Rd) CloseHandle(g_hChildStd_IN_Rd);
	if (g_hChildStd_IN_Wr) CloseHandle(g_hChildStd_IN_Wr);
	if (g_hChildStd_OUT_Rd) CloseHandle(g_hChildStd_OUT_Rd);
	if (g_hChildStd_OUT_Wr) CloseHandle(g_hChildStd_OUT_Wr);
	return ret_code;
}


