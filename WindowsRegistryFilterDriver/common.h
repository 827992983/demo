////By Fanxiushu 2011-10-24

#ifndef _COMMON_H
#define _COMMON_H
 
#pragma warning (disable : 4127)

#define DRIVER_NAME             L"regflt"
#define DRIVER_NAME_WITH_EXT    L"regflt.sys"

#define NT_DEVICE_NAME          L"\\Device\\RegFlt"
#define DOS_DEVICES_LINK_NAME   L"\\DosDevices\\RegFlt"
#define WIN32_DEVICE_NAME       L"\\\\.\\RegFlt"

#define DEVICE_SDDL             L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

#define IOCTL_REGISTER_CALLBACK        CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 1), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_UNREGISTER_CALLBACK      CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 2), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_CALLBACK_VERSION     CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 3), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

//
// Common definitions
// 

#define ROOT_KEY_ABS_PATH          L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute"
#define ROOT_KEY_REL_PATH          L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute"
#define KEY_NAME                   L"_RegFltrKey"
#define MODIFIED_KEY_NAME          L"_RegFltrModifiedKey"
#define NOT_MODIFIED_KEY_NAME      L"_RegFltrNotModifiedKey"
#define VALUE_NAME                 L"_RegFltrValue"
#define MODIFIED_VALUE_NAME        L"_RegFltrModifiedValue"
#define NOT_MODIFIED_VALUE_NAME    L"_RegFltrNotModifiedValue"

#define CALLBACK_LOW_ALTITUDE      L"380000"
#define CALLBACK_ALTITUDE          L"380010"
#define CALLBACK_HIGH_ALTITUDE     L"380020"

#define MAX_ALTITUDE_BUFFER_LENGTH 10

typedef enum _CALLBACK_MODE {
	CALLBACK_MODE_PRE_NOTIFICATION_BLOCK,
	CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
} CALLBACK_MODE;


//
// Input and output data structures for the various driver IOCTLs
//

typedef struct _REGISTER_CALLBACK_INPUT {

	//
	// specifies the callback mode for the callback context
	//
	CALLBACK_MODE CallbackMode;

	//
	// specifies the altitude to register the callback at
	//
	WCHAR Altitude[MAX_ALTITUDE_BUFFER_LENGTH];

} REGISTER_CALLBACK_INPUT, *PREGISTER_CALLBACK_INPUT;

typedef struct _REGISTER_CALLBACK_OUTPUT {

	//
	// receives the cookie value from registering the callback
	//
	LARGE_INTEGER Cookie;

} REGISTER_CALLBACK_OUTPUT, *PREGISTER_CALLBACK_OUTPUT;


typedef struct _UNREGISTER_CALLBACK_INPUT {
	//
	// specifies the cookie value for the callback
	//
	LARGE_INTEGER Cookie;

} UNREGISTER_CALLBACK_INPUT, *PUNREGISTER_CALLBACK_INPUT;


typedef struct _GET_CALLBACK_VERSION_OUTPUT {

	//
	// Receives the version number of the registry callback
	//
	ULONG MajorVersion;
	ULONG MinorVersion;

} GET_CALLBACK_VERSION_OUTPUT, *PGET_CALLBACK_VERSION_OUTPUT;

#endif //_COMMON_H

