#ifndef GLOBAL_DEF_H
#define GLOBAL_DEF_H
#include <QtGlobal>
#include <QDebug>

/* All*/
#define DEBUG

#define APP_NAME "可执行文件解析器"

#ifndef CONST
#define CONST const
#endif

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef float FLOAT;
typedef FLOAT *PFLOAT;
typedef BYTE *PBYTE;
typedef BYTE *LPBYTE;
typedef int *PINT;
typedef int *LPINT;
typedef WORD *PWORD;
typedef WORD *LPWORD;
typedef DWORD *PDWORD;
typedef DWORD *LPDWORD;
typedef void *LPVOID;
typedef CONST void *LPCVOID;
typedef int INT;
typedef unsigned int UINT;
typedef unsigned int *PUINT;
typedef int BOOL;
typedef BOOL *PBOOL;
typedef BOOL *LPBOOL;

#ifdef DEBUG
#define LOG_DEBUG qDebug
#else
#define LOG_DEBUG
#endif

/* Windows */
#ifdef Q_OS_WIN32
#endif

/* Linux */
#ifdef Q_OS_LINUX
#endif

#endif // GLOBAL_DEF_H
