#include "win_common.h"
#include "logger.h"

void Char2Wchar(const char *chr, wchar_t *wchar, int size)
{
	MultiByteToWideChar( CP_ACP, 0, chr, strlen(chr)+1, wchar, size/sizeof(wchar[0]) );
}

void Wchar2Char(const wchar_t *wchar, char *chr, int length)
{
	WideCharToMultiByte( CP_ACP, 0, wchar, -1, chr, length, NULL, NULL );  
}

void Utf8ToWchar(const char *utf8, wchar_t *wchar, int len)
{
	MultiByteToWideChar( CP_UTF8, 0,(char *) utf8, -1, wchar, len ); 
}

void Unicode2Wchar(const char * str, wchar_t *result)
{
	wchar_t rst[1024] = {0};
	bool escape = false;
	int len = strlen(str);
	int intHex;
	char tmp[5];
	int size = 0;
	memset(tmp, 0, 5);
	for (int i = 0; i < len; i++)
	{
		char c = str[i];
		switch (c)
		{
		case '//':
		case '%':
		case '\\':
			escape = true;
			break;
		case 'u':
		case 'U':
			if (escape)
			{
				memcpy(tmp, str+i+1, 4);
				sscanf(tmp, "%x", &intHex);
				rst[size++] = intHex;
				i+=4;
				escape=false;
			}else{
				rst[size++] = c;
			}
			break;
		default:
			rst[size++] = c;
			break;
		}
	}
	wcscpy(result, rst);
	return;
}

char *trim(char *str)
{
	register char *s, *t;

	if (str == NULL)
	{
		return NULL;
	}

	for (s = str; isspace (*s); s++)
		;

	if (*s == 0)
		return s;

	t = s + strlen (s) - 1;
	while (t > s && isspace (*t))
		t--;
	*++t = '\0';

	return s;
}

unsigned long CheckFileSize(const char *path)
{  
	unsigned long filesize = -1;  
	FILE *fp;  
	fp = ::fopen(path, "r");  
	if(fp == NULL)  
		return filesize;  
	fseek(fp, 0L, SEEK_END);  
	filesize = ftell(fp);  
	fclose(fp);  
	return filesize;
}

bool DirectoryIsExist(const TCHAR *path)  
{  
	DWORD ftyp = GetFileAttributes(path);  
	if (ftyp == INVALID_FILE_ATTRIBUTES)  
		return false;

	if (ftyp & FILE_ATTRIBUTE_DIRECTORY)  
		return true;  

	return false;  
}

int CreateQingCloudDirectory(void)
{
	if (DirectoryIsExist(WINDOWS_TEMP_PATH))
	{
		if(!DirectoryIsExist(WINDOWS_TEMP_LOG_PATH)){
			if (!CreateDirectory(WINDOWS_TEMP_LOG_PATH, NULL)){
				LOG_ERROR("create log directory [%s] error!", WINDOWS_TEMP_LOG_PATH);
				return -1;
			}
		}

		if(!DirectoryIsExist(WINDOWS_TEMP_CONFIG_PATH)){
			if (!CreateDirectory(WINDOWS_TEMP_CONFIG_PATH, NULL)){
				LOG_ERROR("create config directory [%s] error!", WINDOWS_TEMP_CONFIG_PATH);
				return -1;
			}
		}
	}else{
		if (!CreateDirectory(WINDOWS_TEMP_PATH, NULL)){
			LOG_ERROR("create QingCloud directory [%s] error!", WINDOWS_TEMP_PATH);
			return -1;
		}

		if (!CreateDirectory(WINDOWS_TEMP_CONFIG_PATH, NULL)){
			LOG_ERROR("create config directory [%s] error!", WINDOWS_TEMP_CONFIG_PATH);
			return -1;
		}

		if (!CreateDirectory(WINDOWS_TEMP_LOG_PATH, NULL)){
			LOG_ERROR("create log directory [%s] error!", WINDOWS_TEMP_LOG_PATH);
			return -1;
		}
	}

	return 0;
}

#pragma comment(lib, "Psapi.lib")
DWORD GetProcessIDFromName(TCHAR *name)
{
	HANDLE snapshot;
	PROCESSENTRY32 processinfo;
	processinfo.dwSize = sizeof(processinfo);
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == NULL)
		return FALSE;

	BOOL status = Process32First(snapshot, &processinfo);
	while (status)
	{
		if (_tcscmp(name, processinfo.szExeFile) == 0)
			return processinfo.th32ProcessID;
		status = Process32Next(snapshot, &processinfo);
	}
	return -1;
}

bool GetCurrentLoginUser(TCHAR *lpUserName, DWORD nNameLen)
{
	DWORD dwProcessID = GetProcessIDFromName(_T("explorer.exe"));
	if (dwProcessID == 0)
		return false;

	BOOL fResult = FALSE;
	HANDLE hProc = NULL;
	HANDLE hToken = NULL;
	TOKEN_USER *pTokenUser = NULL;

	// Open the process with PROCESS_QUERY_INFORMATION access
	hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessID);
	if (hProc == NULL)
	{
		return false;
	}
	fResult = OpenProcessToken(hProc, TOKEN_QUERY, &hToken);
	if (!fResult)
	{
		if (hProc)
			::CloseHandle(hProc);
		return false;
	}

	DWORD dwNeedLen = 0;
	fResult = GetTokenInformation(hToken, TokenUser, NULL, 0, &dwNeedLen);
	if (dwNeedLen > 0)
	{
		pTokenUser = (TOKEN_USER*)new BYTE[dwNeedLen];
		fResult = GetTokenInformation(hToken, TokenUser, pTokenUser, dwNeedLen, &dwNeedLen);
		if (!fResult)
		{
			if (hProc)
				::CloseHandle(hProc);
			if (hToken)
				::CloseHandle(hToken);
			if (pTokenUser)
				delete[](char*)pTokenUser;
			return false;
		}
	}
	else
	{
		if (hProc)
			::CloseHandle(hProc);
		if (hToken)
			::CloseHandle(hToken);
		return false;
	}

	SID_NAME_USE sn;
	TCHAR szDomainName[MAX_PATH];
	DWORD dwDmLen = MAX_PATH;

	fResult = LookupAccountSid(NULL, pTokenUser->User.Sid, lpUserName, &nNameLen,szDomainName, &dwDmLen, &sn);
	return true;
}

#pragma warning(disable: 4996)
SystemVersion supported_system_version()
{
	OSVERSIONINFOEX osvi;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (!GetVersionEx((OSVERSIONINFO*)&osvi)) {
		return SYS_VER_UNSUPPORTED;
	}
	if (osvi.dwMajorVersion == 5 && (osvi.dwMinorVersion == 1 || osvi.dwMinorVersion == 2)) {
		return SYS_VER_WIN_XP_CLASS;
	}
	else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion >= 0 && osvi.dwMinorVersion <= 2) {
		return SYS_VER_WIN_7_CLASS;
	}
	return SYS_VER_UNSUPPORTED;
}
