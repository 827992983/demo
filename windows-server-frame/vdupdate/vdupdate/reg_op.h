#include <windows.h>

int find_reg_key(HKEY hKey, LPCTSTR lpSubKey);
int create_reg_key(HKEY hKey, LPCTSTR lpSubKey);
int get_reg_value(HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
int set_reg_value(HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName, DWORD dwType, const BYTE *lpData, DWORD cbData);
int delete_reg_value(HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName);
int delete_reg_key(HKEY hKey, LPCTSTR lpSubKey);
