/*++
Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.

Module Name:

    Pre.c

Abstract: 

    Samples that show what callbacks can do during the pre-notification
    phase.

Environment:

    User mode only

--*/



#include "regctrl.h"


VOID PreNotificationBlock(LARGE_INTEGER *cookie)
{
    HRESULT hr;
    DWORD BytesReturned;
    BOOL Result;
    REGISTER_CALLBACK_INPUT RegisterCallbackInput = {0};
    REGISTER_CALLBACK_OUTPUT RegisterCallbackOutput = {0};

    InfoPrint("");
    InfoPrint("=== Pre-Notification Block Sample ====");
 
    RtlZeroMemory(RegisterCallbackInput.Altitude, MAX_ALTITUDE_BUFFER_LENGTH * sizeof(WCHAR));
    hr = StringCbPrintf(RegisterCallbackInput.Altitude, 
                          MAX_ALTITUDE_BUFFER_LENGTH * sizeof(WCHAR),
                          CALLBACK_ALTITUDE);

    if (!SUCCEEDED(hr)) {
        ErrorPrint("Copying altitude string failed. Error %d", hr);
		return;
    }

    RegisterCallbackInput.CallbackMode = CALLBACK_MODE_PRE_NOTIFICATION_BLOCK;

    Result = DeviceIoControl(g_Driver,
                             IOCTL_REGISTER_CALLBACK,
                             &RegisterCallbackInput,
                             sizeof(REGISTER_CALLBACK_INPUT),
                             &RegisterCallbackOutput,
                             sizeof(REGISTER_CALLBACK_OUTPUT),
                             &BytesReturned,
                             NULL);

    if (Result != TRUE) {    
        ErrorPrint("RegisterCallback failed. Error %d", GetLastError());
    }

	if (cookie)
		*cookie = RegisterCallbackOutput.Cookie;
  
}

void UnRegisterBlock(LARGE_INTEGER Cookie) {
	BOOL Result;
	DWORD BytesReturned;
	UNREGISTER_CALLBACK_INPUT UnRegisterCallbackInput = { 0 };
	UnRegisterCallbackInput.Cookie = Cookie;

	Result = DeviceIoControl(g_Driver,
		IOCTL_UNREGISTER_CALLBACK,
		&UnRegisterCallbackInput,
		sizeof(UNREGISTER_CALLBACK_INPUT),
		NULL,
		0,
		&BytesReturned,
		NULL);

	if (Result != TRUE) {
		ErrorPrint("UnRegisterCallback failed. Error %d", GetLastError());
	}
}


VOID 
PreNotificationBypass()
{
    HRESULT hr;
    BOOL Result;
    DWORD BytesReturned;
    REGISTER_CALLBACK_INPUT RegisterCallbackInput = {0};
    REGISTER_CALLBACK_OUTPUT RegisterCallbackOutput = {0};

    RtlZeroMemory(RegisterCallbackInput.Altitude, 
                  MAX_ALTITUDE_BUFFER_LENGTH * sizeof(WCHAR));

    hr = StringCbPrintf(RegisterCallbackInput.Altitude, 
                          MAX_ALTITUDE_BUFFER_LENGTH * sizeof(WCHAR),
                          CALLBACK_ALTITUDE);

    if (!SUCCEEDED(hr)) {
        ErrorPrint("Copying altitude string failed. Error %d", hr);
        return ;
    }

    RegisterCallbackInput.CallbackMode = CALLBACK_MODE_PRE_NOTIFICATION_BYPASS;

    Result = DeviceIoControl(g_Driver,
                             IOCTL_REGISTER_CALLBACK,
                             &RegisterCallbackInput,
                             sizeof(REGISTER_CALLBACK_INPUT),
                             &RegisterCallbackOutput,
                             sizeof(REGISTER_CALLBACK_OUTPUT),
                             &BytesReturned,
                             NULL);

    if (Result != TRUE) {    
        ErrorPrint("RegisterCallback failed. Error %d", GetLastError());
    }
}

