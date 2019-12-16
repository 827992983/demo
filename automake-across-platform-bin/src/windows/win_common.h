#ifndef _COMMON_H__
#define _COMMON_H__
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#define WINDOWS_TEMP_PATH TEXT("C:\\Windows\\Temp\\QingCloud")
#define WINDOWS_TEMP_LOG_PATH TEXT("C:\\Windows\\Temp\\QingCloud\\log")
#define WINDOWS_TEMP_CONFIG_PATH TEXT("C:\\Windows\\Temp\\QingCloud\\config")

void Char2Wchar(const char *chr, wchar_t *wchar, int size/*w_char buf size*/);
void Wchar2Char(const wchar_t *wchar, char *chr, int length/*char buf size*/);
void Utf8ToWchar(const char *utf8, wchar_t *wchar, int len/*wchar buf size*/);
void Unicode2Wchar(const char * str, wchar_t *result);
char *trim(char *str);
unsigned long CheckFileSize(const char *path);
bool DirectoryIsExist(const TCHAR *path);
int CreateQingCloudDirectory(void);
DWORD GetProcessIDFromName(TCHAR *name);
bool GetCurrentLoginUser(TCHAR *lpUserName, DWORD nNameLen);

#endif
