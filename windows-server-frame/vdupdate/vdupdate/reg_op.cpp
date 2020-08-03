#include "stdafx.h"
#include "reg_op.h"
#include <tchar.h>

int find_reg_key(HKEY hKey, LPCTSTR lpSubKey)
{
	HKEY hKeyRet;
#ifdef _WIN64  
	if (ERROR_SUCCESS == ::RegOpenKeyEx(hKey, lpSubKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKeyRet))
#else
	if (ERROR_SUCCESS == ::RegOpenKeyEx(hKey, lpSubKey, 0, KEY_READ, &hKeyRet))
#endif
	{
		RegCloseKey(hKeyRet);
	}
	else
	{
		return -1;
	}
	return 0;
}

int create_reg_key(HKEY hKey, LPCTSTR lpSubKey)
{
	HKEY hKeyRet;
	TCHAR *sSubKey = NULL;
	TCHAR *sChildKey = NULL;
	long lLastError = ERROR_SUCCESS;
	TCHAR szKey[260] = { 0 };
	int flag = 0;

	sSubKey = (TCHAR *)malloc(sizeof(TCHAR) * 260);
	_tcscpy(sSubKey, lpSubKey);
	sChildKey = _tcstok(sSubKey,  _T("\\"));
	while (sChildKey != NULL && _tcslen(sChildKey)>0)
	{
		if (flag > 0)
		{
			_tcscat(szKey, (TCHAR *)"\\");
		}
		_tcscat(szKey, sChildKey);
		flag = 1;
		if (find_reg_key(hKey, szKey) != 0)
		{
			lLastError = RegCreateKey(hKey, szKey, &hKeyRet);
			RegCloseKey(hKeyRet);
		}
		if (ERROR_SUCCESS != lLastError)
			break;
		sChildKey = _tcstok(NULL, (TCHAR *)"\\");
	}

	free(sSubKey);
	sSubKey = NULL;

	if (ERROR_SUCCESS != lLastError)
	{
		return -1;
	}
	return 0;
}


int get_reg_value(HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	HKEY hKeyRet;

#ifdef _WIN64  
	if (ERROR_SUCCESS == ::RegOpenKeyEx(hKey, lpSubKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKeyRet))
#else
	if (ERROR_SUCCESS == ::RegOpenKeyEx(hKey, lpSubKey, 0, KEY_READ, &hKeyRet))
#endif
	{
		if (::RegQueryValueEx(hKeyRet, lpValueName, 0, lpType, lpData, lpcbData) != ERROR_SUCCESS)
		{
			::RegCloseKey(hKeyRet);
			return -1;
		}
	}
	::RegCloseKey(hKeyRet);
	return 0;
}

int set_reg_value(HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName, DWORD dwType, const BYTE *lpData, DWORD cbData)
{
	HKEY hKeyRet;

#ifdef _WIN64  
	if (ERROR_SUCCESS == ::RegOpenKeyEx(hKey, lpSubKey, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKeyRet))
#else
	if (ERROR_SUCCESS == ::RegOpenKeyEx(hKey, lpSubKey, 0, KEY_READ, &hKeyRet))
#endif
	{
		if (ERROR_SUCCESS != ::RegSetValueEx(hKeyRet, lpValueName, 0, dwType, lpData, cbData))
		{
			return -1;
		}
	}
	::RegCloseKey(hKeyRet);
	return 0;
}

int delete_reg_value(HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName)
{
	HKEY hKeyRet;

#ifdef _WIN64  
	if (ERROR_SUCCESS == ::RegOpenKeyEx(hKey, lpSubKey, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKeyRet))
#else
	if (ERROR_SUCCESS == ::RegOpenKeyEx(hKey, lpSubKey, 0, KEY_READ, &hKeyRet))
#endif
	{
		if (ERROR_SUCCESS != ::RegDeleteValue(hKeyRet, lpValueName))
		{
			::RegCloseKey(hKeyRet);
			return -1;
		}
	}
	::RegCloseKey(hKeyRet);
	return 0;
}

int delete_reg_key(HKEY hKey, LPCTSTR lpSubKey)
{
	if (ERROR_SUCCESS != ::RegDeleteKey(hKey, lpSubKey))
	{
		return -1;
	}
	return 0;
}

