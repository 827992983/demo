#ifndef _COMMON_H__
#define _COMMON_H__
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>

#define WINDOWS_TEMP_PATH TEXT("C:\\Windows\\Temp\\QingCloud")
#define WINDOWS_TEMP_LOG_PATH TEXT("C:\\Windows\\Temp\\QingCloud\\logs")
#define WINDOWS_TEMP_CONFIG_PATH TEXT("C:\\Windows\\Temp\\QingCloud\\configs")


#if !defined __GNUC__
#pragma warning(disable:4200)
#endif

#include <errno.h>
#include <windows.h>

class Mutex {
public:
	Mutex() {
		InitializeCriticalSection(&_crit);
	}
	~Mutex() {
		DeleteCriticalSection(&_crit);
	}
	void lock() {
		EnterCriticalSection(&_crit);
	}
	void unlock() {
		LeaveCriticalSection(&_crit);
	}
private:
	CRITICAL_SECTION _crit;
	// no copy
	Mutex(const Mutex&);
	void operator=(const Mutex&);
};

class MutexLocker {
public:
	MutexLocker(Mutex &mtx) :_mtx(mtx) {
		_mtx.lock();
	}
	~MutexLocker() {
		_mtx.unlock();
	}
private:
	Mutex &_mtx;
	// no copy
	MutexLocker(const MutexLocker&);
	void operator=(const MutexLocker&);
};
typedef Mutex mutex_t;

enum SystemVersion {
	SYS_VER_UNSUPPORTED,
	SYS_VER_WIN_XP_CLASS, // also Server 2003/R2
	SYS_VER_WIN_7_CLASS,  // also Windows 8, Server 2012, Server 2008/R2 & Vista
};

SystemVersion supported_system_version();


// function
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
