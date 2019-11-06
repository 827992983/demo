#pragma once
#ifdef __cplusplus
extern "C" {
#include <wdm.h>
}
#else
#include <wdm.h>
#endif

#include <ntstrsafe.h>
#include <wdmsec.h>

#include "common.h"

#define REGFLTR_POOL_TAG          'regf'

#define InfoPrint(str, ...)                 \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,         \
               DPFLTR_INFO_LEVEL,           \
               "%S: "##str"\n",             \
               DRIVER_NAME,                 \
               __VA_ARGS__)

#define ErrorPrint(str, ...)                \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,         \
               DPFLTR_ERROR_LEVEL,          \
               "%S: %d: "##str"\n",         \
               DRIVER_NAME,                 \
               __LINE__,                    \
               __VA_ARGS__)

extern PDEVICE_OBJECT g_DeviceObj;


extern ULONG g_MajorVersion;
extern ULONG g_MinorVersion;

#define MAX_CALLBACK_CTX_ENTRIES            10

extern FAST_MUTEX g_CallbackCtxListLock;

extern LIST_ENTRY g_CallbackCtxListHead;

extern USHORT g_NumCallbackCtxListEntries;

typedef struct _CALLBACK_CONTEXT {
	LIST_ENTRY CallbackCtxList;

	CALLBACK_MODE CallbackMode;

	HANDLE ProcessId;

	UNICODE_STRING Altitude;
	WCHAR AltitudeBuffer[MAX_ALTITUDE_BUFFER_LENGTH];

	LARGE_INTEGER Cookie;

	LONG ContextCleanupCount;

	LONG NotificationWithContextCount;

	LONG NotificationWithNoContextCount;

	LONG PreNotificationCount;

	LONG PostNotificationCount;

} CALLBACK_CONTEXT, *PCALLBACK_CONTEXT;

EX_CALLBACK_FUNCTION Callback;

NTSTATUS
CallbackPreNotificationBlock(
	_In_ PCALLBACK_CONTEXT CallbackCtx,
	_In_ REG_NOTIFY_CLASS NotifyClass,
	_Inout_ PVOID Argument2
);

NTSTATUS
CallbackPreNotificationBypass(
	_In_ PCALLBACK_CONTEXT CallbackCtx,
	_In_ REG_NOTIFY_CLASS NotifyClass,
	_Inout_ PVOID Argument2
);

NTSTATUS
RegisterCallback(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

NTSTATUS
UnRegisterCallback(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

NTSTATUS
GetCallbackVersion(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

PVOID
CreateCallbackContext(
	_In_ CALLBACK_MODE CallbackMode,
	_In_ PCWSTR AltitudeString
);

BOOLEAN
InsertCallbackContext(
	_In_ PCALLBACK_CONTEXT CallbackCtx
);

PCALLBACK_CONTEXT
FindCallbackContext(
	_In_ LARGE_INTEGER Cookie
);

PCALLBACK_CONTEXT
FindAndRemoveCallbackContext(
	_In_ LARGE_INTEGER Cookie
);

VOID
DeleteCallbackContext(
	_In_ PCALLBACK_CONTEXT CallbackCtx
);

NTSTATUS DeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

#pragma warning(pop)