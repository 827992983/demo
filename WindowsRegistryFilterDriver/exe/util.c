#include "regctrl.h"


BOOL 
UtilCreateService(
    _In_ SC_HANDLE hSCM, 
    _In_ LPTSTR szDriverName, 
    _In_ LPTSTR szDriverPath
);

BOOL 
UtilStartService(
    _In_ SC_HANDLE hSCM, 
    _In_ LPTSTR szDriverName
);

BOOL 
UtilStopService(
    _In_ SC_HANDLE hSCM, 
    _In_ LPTSTR szDriverName
);

BOOL 
UtilDeleteService(
    _In_ SC_HANDLE hSCM, 
    _In_ LPTSTR szDriverName
);


BOOL 
UtilWaitForServiceState(
    _In_ SC_HANDLE hService, 
    _In_ DWORD State);


BOOL 
UtilLoadDriver(
    _In_ LPTSTR szDriverName,
    _In_ LPTSTR szDriverFileName
    )
{
    BOOL ReturnValue = FALSE;
    TCHAR* pPathSeparator;
    TCHAR szDriverPath[MAX_PATH] = _T("");
    DWORD dwSize;
    SC_HANDLE hSCM = NULL;

    dwSize = GetModuleFileName(NULL, szDriverPath, ARRAY_LENGTH(szDriverPath));
    
    if (dwSize == 0) {
        ErrorPrint("GetModuleFileName failed, last error 0x%u", GetLastError());
        goto Exit;
    }

    pPathSeparator = _tcsrchr(szDriverPath, _T('\\'));

    if (pPathSeparator != NULL) {
        pPathSeparator[1] = _T('\0');
        _tcscat_s(szDriverPath, MAX_PATH, szDriverFileName);
    } else {
        ErrorPrint("_tcsrchr failed to file \\ in driver path.");
        goto Exit;
    }

    hSCM = OpenSCManager ( NULL, NULL, SC_MANAGER_ALL_ACCESS );

    if (hSCM == NULL) {
        ErrorPrint("OpenSCManager failed, last error 0x%x", GetLastError());
        goto Exit;
    }

    //
    // First, uninstall and unload the driver. 
    //

    ReturnValue = UtilUnloadDriver(szDriverName);

    if (ReturnValue != TRUE) {
        ErrorPrint("UnloadDriver failed");
        goto Exit;
    }

    //
    // Install the driver.
    //

    ReturnValue = UtilCreateService(hSCM, szDriverName, szDriverPath);

    if (ReturnValue == FALSE) {
        ErrorPrint("UtilCreateService failed");
        goto Exit;
    }

Exit:

    if (hSCM != NULL) {
        CloseServiceHandle(hSCM);
    }
    
    return ReturnValue;
}


BOOL UtilUnloadDriver(_In_ LPTSTR szDriverName)
{

    BOOL ReturnValue = FALSE;
    SC_HANDLE hSCM ;

    hSCM = OpenSCManager ( NULL, NULL, SC_MANAGER_ALL_ACCESS );

    if (hSCM == NULL) {
         ErrorPrint("OpenSCManager failed, last error 0x%x", GetLastError());
        goto Exit;
    }

    ReturnValue = UtilDeleteService(hSCM, szDriverName);

    if (ReturnValue == FALSE) {
        ErrorPrint("UtilDeleteService failed");
        goto Exit;
    }

    ReturnValue = TRUE;

Exit:

    if ((hSCM != NULL)) {
        CloseServiceHandle(hSCM);
    }
    
    return ReturnValue;
}



BOOL 
UtilGetServiceState (
    _In_ SC_HANDLE hService,
    _Out_ DWORD* State
    )
{
    SERVICE_STATUS_PROCESS ServiceStatus;
    DWORD BytesNeeded;
    BOOL Result;
    
    *State = 0;

    Result = QueryServiceStatusEx ( hService,
                                         SC_STATUS_PROCESS_INFO,
                                         (LPBYTE)&ServiceStatus,
                                         sizeof(ServiceStatus),
                                         &BytesNeeded);

    if (Result == FALSE) {
        ErrorPrint("QueryServiceStatusEx failed, last error 0x%x", GetLastError());
        return FALSE;
    }

    *State = ServiceStatus.dwCurrentState;

    return TRUE;
}


BOOL 
UtilWaitForServiceState (
    _In_ SC_HANDLE hService,
    _In_ DWORD State
    )
{

    DWORD ServiceState;
    BOOL Result; 
    
    for (;;) {

        Result = UtilGetServiceState (hService, &ServiceState);

        if (Result == FALSE) {
            return FALSE;
        }

        if (ServiceState == State) {
            break;
        }

        Sleep (1000);
    }

    return TRUE;
}

BOOL 
UtilCreateService(
    _In_ SC_HANDLE hSCM,
    _In_ LPTSTR szDriverName,
    _In_ LPTSTR szDriverPath
    )
{
    BOOL ReturnValue = FALSE;

    SC_HANDLE hService = CreateService (
        hSCM,                 // handle to SC manager
        szDriverName,         // name of service
        szDriverName,         // display name
        SERVICE_ALL_ACCESS,     // access mask
        SERVICE_KERNEL_DRIVER,  // service type
		SERVICE_SYSTEM_START,   // start type
        SERVICE_ERROR_NORMAL,   // error control
        szDriverPath,           // full path to driver
        NULL,                   // load ordering
        NULL,                   // tag id
        NULL,                   // dependency
        NULL,                   // account name
        NULL                    // password
    );

    if ((hService == NULL) && (GetLastError() != ERROR_SERVICE_EXISTS)) {
        ErrorPrint("CreateService failed, last error 0x%x", GetLastError());
        goto Exit;
    }

    ReturnValue = TRUE;

Exit:

    if (hService) {
        CloseServiceHandle(hService);
    }

    return ReturnValue;
}


BOOL 
UtilStartService(
    _In_ SC_HANDLE hSCM,
    _In_ LPTSTR szDriverName
    )
{
    BOOL ReturnValue = FALSE;

    SC_HANDLE hService = OpenService ( hSCM, szDriverName, SERVICE_ALL_ACCESS );

    if (hService == NULL) {
        ErrorPrint("OpenService failed, last error 0x%x", GetLastError());
        goto Exit;
    }

    if (! StartService (hService, 0, NULL)) {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            ErrorPrint("StartService failed, last error 0x%x", GetLastError());
            goto Exit;
        }
    }

    if (FALSE == UtilWaitForServiceState (hService, SERVICE_RUNNING)) {
        goto Exit;
    }
    
    ReturnValue = TRUE;

Exit:

    if (hService) {
        CloseServiceHandle(hService);
    }

    return ReturnValue;
}


BOOL 
UtilStopService(
    _In_ SC_HANDLE hSCM,
    _In_ LPTSTR szDriverName
    )
{
    BOOL ReturnValue = FALSE;
    SERVICE_STATUS ServiceStatus;

    SC_HANDLE hService = OpenService ( hSCM, szDriverName, SERVICE_ALL_ACCESS );

    if (hService == NULL) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
            ReturnValue = TRUE;
        } else {
            ErrorPrint("OpenService failed, last error 0x%x", GetLastError());
        }
        goto Exit;
    }


    if (FALSE == ControlService (hService, SERVICE_CONTROL_STOP, &ServiceStatus)) {
        if (GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
            ErrorPrint("ControlService failed, last error 0x%x", GetLastError());
            goto Exit;
        }
    }

    if (FALSE == UtilWaitForServiceState (hService, SERVICE_STOPPED)) {
        goto Exit;
    }
    
    ReturnValue = TRUE;

Exit:

    if (hService) {
        CloseServiceHandle (hService);
    }

    return ReturnValue;
}


BOOL 
UtilDeleteService(
    _In_ SC_HANDLE hSCM,
    _In_ LPTSTR szDriverName
    )
/*++

Routine Description:

    Deletes a service

Arguments:

    hSCM - handle to the SCManager

    szDriverName - name of driver (without extension), services as name of
        the service

Return Value:

    TRUE if service is successfully deleted, FALSE otherwise.

--*/
{
    BOOL ReturnValue = FALSE;

    //
    // Open the service so we can delete it
    //

    SC_HANDLE hService = OpenService ( hSCM, szDriverName, SERVICE_ALL_ACCESS );

    if (hService == NULL) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
            ReturnValue = TRUE;
        } else {
            ErrorPrint("OpenService failed, last error 0x%x", GetLastError());
        }
       goto Exit;
    }

    //
    // Delete the service
    //

    if (! DeleteService (hService)) {
        if (GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE) {
            ErrorPrint("DeleteService failed, last error 0x%x", GetLastError());
            goto Exit;
        }
    }

    ReturnValue = TRUE;

Exit:

    if (hService) {
        CloseServiceHandle (hService);
    }

    return ReturnValue;
}


BOOL 

UtilOpenDevice(
    _In_ LPTSTR szWin32DeviceName,
    _Out_ HANDLE *phDevice
    )
{
    BOOL ReturnValue = FALSE;
    HANDLE hDevice;

    hDevice = CreateFile ( szWin32DeviceName,
                           GENERIC_READ | GENERIC_WRITE,
                           0,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        ErrorPrint("CreateFile(%ls) failed, last error 0x%x", 
                    szWin32DeviceName, 
                    GetLastError() );
        goto Exit;
    }

    ReturnValue = TRUE;

Exit:

    *phDevice = hDevice;
    return ReturnValue;
}
