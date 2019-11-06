#include <windows.h>
#include <winternl.h>
#include <wtsapi32.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stdarg.h>
#include <winsvc.h>
#include <aclapi.h>
#include <time.h>
#include "regctrl.h"



typedef struct _VDService {
	SERVICE_STATUS _status;
	SERVICE_STATUS_HANDLE _status_handle;
}VDService;

typedef struct _registery_ctrl {
	DWORD op;
	DWORD len;
}registery_ctrl;

typedef struct pipe_read {
	OVERLAPPED ov;
	HANDLE hNamePipe;
	DWORD size;
	registery_ctrl ctrl;
	PWCH data;
}PIPEOVERLAPPED, *LPPIPEOVERLAPPED;


#define LOG_ROLL_SIZE (1024 * 1024)

#define REGFLT_SERVICE_NAME         TEXT("regfilter")
#define REGFLT_SERVICE_ACCEPTED_CONTROLS (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN )
#define REGFLT_SERVICE_DISPLAY_NAME TEXT("Registery Filter")
#define REGFLT_SERVICE_LOG_PATH     TEXT("%s\\regfltservice.log")
#define REGFLT_SERVICE_DESCRIPTION  TEXT("Registery Filter for protecting special register value.")
#define REGFLT_SERVICE_LOAD_ORDER_GROUP TEXT("Register Service")


#define WINDOWS_TEMP_PATH TEXT("C:\\Windows\\Temp\\QingCloud")
#define WINDOWS_TEMP_LOG_PATH TEXT("C:\\Windows\\Temp\\QingCloud\\log")

#define PID GetCurrentProcessId()
#define TID GetCurrentThreadId()


#define REG_FLT_SERVICE_LOG_FILE "C:\\Windows\\Temp\\QingCloud\\log\\regfltservice.log"
enum {
	LOG_DEBUG,
	LOG_WARN,
	LOG_ERROR
};
void log_init(const char *log_file);
void log_write(unsigned int type, const char *file, const char *function, const int line, const char *format, ...);
void log_cleanup(void);
#define LOG(type, format, ...) log_write(type, __FILE__, __FUNCTION__, __LINE__, format, ## __VA_ARGS__)
#define LOG_DEBUG(format, ...) LOG(LOG_DEBUG, format, ## __VA_ARGS__)
#define LOG_WARN(format, ...) LOG(LOG_WARN, format, ## __VA_ARGS__)
#define LOG_ERROR(format, ...) LOG(LOG_ERROR, format, ## __VA_ARGS__)

#define LOCK_INIT(x) CreateMutex(NULL,FALSE,x)
#define LOCK(x) WaitForSingleObject(x, INFINITE)
#define UNLOCK(x) ReleaseMutex(x)
#define LOCK_DESTROY(x) CloseHandle(x)


FILE* handle = NULL;
HANDLE g_Driver;
HANDLE hStopEvent = NULL ;
volatile BOOL running;

static unsigned int log_level = LOG_DEBUG;
static FILE *log_file = NULL;
static HANDLE log_mutex = NULL;
unsigned long get_file_size(const char *path)
{
	unsigned long filesize = 0;
	if (!path) {
		return filesize;
	}

	HANDLE file = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (file != INVALID_HANDLE_VALUE) {
		CloseHandle(file);
	}
	FILE *fp;
	fp = fopen(path, "r");
	if (fp == NULL)
		return filesize;
	fseek(fp, 0L, SEEK_END);
	filesize = ftell(fp);
	fclose(fp);
	return filesize;
}
void log_init(const char *log_file_name)
{
	unsigned long filesize = get_file_size(log_file_name);
	if (filesize > LOG_ROLL_SIZE) {
		DeleteFileA(log_file_name);
	}
	log_file = fopen(log_file_name, "a");
	if (log_file == NULL) {
		fprintf(stderr, "Failed to open log file %s\n", log_file_name);
		return;
	}
	log_mutex = LOCK_INIT(NULL);
	if (log_mutex == NULL) {
		fprintf(stderr, "Failed to open log file %s\n", log_file_name);
		return;
	}
}
void log_cleanup(void)
{
	if (log_file) {
		fclose(log_file);
		log_file = NULL;
	}
	LOCK_DESTROY(log_mutex);
}
void log_write(unsigned int type, const char *file, const char *function, const int line, const char *format, ...)
{
	FILE *out_file;
	va_list para;
	const char *type_as_char[] = { "DEBUG", "WARN", "ERROR" };
	if (type < log_level) {
		return;
	}
	LOCK(log_mutex);
	out_file = log_file ? log_file : stderr;
	va_start(para, format);
	fprintf(out_file, "%ld %s %s:%s:%d pid:%d,tid:%d: ", (long)time(NULL), type_as_char[type], file, function, line, PID, TID);
	vfprintf(out_file, format, para);
	va_end(para);
	fprintf(out_file, "\n");
	fflush(out_file);
	UNLOCK(log_mutex);
	return;
}

BOOL DirectoryIsExist(const TCHAR *path)
{
	DWORD ftyp = GetFileAttributes(path);
	if (ftyp == INVALID_FILE_ATTRIBUTES)
		return FALSE;
	if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
		return TRUE;
	return FALSE;
}
int CreateQingCloudDirectory(void)
{
	if (DirectoryIsExist(WINDOWS_TEMP_PATH))
	{
		if (!DirectoryIsExist(WINDOWS_TEMP_LOG_PATH)) {
			if (!CreateDirectory(WINDOWS_TEMP_LOG_PATH, NULL)) {
				LOG_DEBUG("create log directory [%s] error!", WINDOWS_TEMP_LOG_PATH);
				return -1;
			}
		}
	}
	else {
		if (!CreateDirectory(WINDOWS_TEMP_PATH, NULL)) {
			LOG_DEBUG("create QingCloud directory [%s] error!", WINDOWS_TEMP_PATH);
			return -1;
		}
		if (!CreateDirectory(WINDOWS_TEMP_LOG_PATH, NULL)) {
			LOG_DEBUG("create log directory [%s] error!", WINDOWS_TEMP_LOG_PATH);
			return -1;
		}
	}
	return 0;
}

DWORD WINAPI control_handler(DWORD control, DWORD event_type, LPVOID event_data, LPVOID context);

BOOL execute()
{
	DWORD wait_ret;

	hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (hStopEvent == NULL)
	{
		LOG_DEBUG("CreateEvent failed with %d.\n", GetLastError());
		return FALSE;
	}
	
	running = TRUE;

	LOG_DEBUG("execute");

	while (running) {
		wait_ret = WaitForSingleObjectEx(hStopEvent, INFINITE, TRUE);
		if (wait_ret == WAIT_OBJECT_0 ) {
			ResetEvent(hStopEvent);
			running = FALSE;
		}
		else {
			running = FALSE;
		}
	}

	LOG_DEBUG("after execute");

	return TRUE;
}

VOID WINAPI main_func(DWORD argc, TCHAR* argv[])
{
	SERVICE_STATUS *status;
	VDService* s;
	s = (VDService*)calloc(1, sizeof(VDService));
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);


	if (CreateQingCloudDirectory()==0) {
		log_init(REG_FLT_SERVICE_LOG_FILE);
	}
	else
		LOG_DEBUG("create directory error %d", GetLastError());

	LOG_DEBUG("***Service started***");

	status = &s->_status;
	status->dwServiceType = SERVICE_WIN32;
	status->dwCurrentState = SERVICE_STOPPED;
	status->dwControlsAccepted = 0;
	status->dwWin32ExitCode = NO_ERROR;
	status->dwServiceSpecificExitCode = NO_ERROR;
	status->dwCheckPoint = 0;
	status->dwWaitHint = 0;

	s->_status_handle = RegisterServiceCtrlHandlerEx(REGFLT_SERVICE_NAME, &control_handler, s);
	if (!s->_status_handle) {
		LOG_DEBUG("RegisterServiceCtrlHandler failed %d.", GetLastError());
		return;
	}

	// service is starting
	status->dwCurrentState = SERVICE_START_PENDING;
	SetServiceStatus(s->_status_handle, status);

	// service running
	status->dwControlsAccepted |= REGFLT_SERVICE_ACCEPTED_CONTROLS;
	status->dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(s->_status_handle, status);

	execute();

	status->dwCurrentState = SERVICE_STOP_PENDING;
	SetServiceStatus(s->_status_handle, status);

	// service is stopped
	status->dwControlsAccepted &= ~REGFLT_SERVICE_ACCEPTED_CONTROLS;
	status->dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(s->_status_handle, status);

	LOG_DEBUG("***Service stopped***");
	log_cleanup();

	free(s);
	CloseHandle(g_Driver);
}

BOOL run()
{
	LARGE_INTEGER cookie;
	BOOL ReturnValue;

	UtilOpenDevice(WIN32_DEVICE_NAME,&g_Driver);
	PreNotificationBlock(&cookie);
	SERVICE_TABLE_ENTRY service_table[] = {
		{ (LPTSTR)(REGFLT_SERVICE_NAME), main_func },{ 0, 0 } };
	ReturnValue = !!StartServiceCtrlDispatcher(service_table);
	UnRegisterBlock(cookie);
	return ReturnValue;
}

BOOL install()
{
	BOOL ret = FALSE;
	SC_HANDLE service_control_manager;


	UtilLoadDriver(DRIVER_NAME, DRIVER_NAME_WITH_EXT);

	service_control_manager = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
	if (!service_control_manager) {
		printf("OpenSCManager failed\n");
		return FALSE;
	}
	TCHAR path[_MAX_PATH + 2];
	DWORD len = GetModuleFileName(0, path + 1, _MAX_PATH);
	if (len == 0 || len == _MAX_PATH) {
		printf("GetModuleFileName failed\n");
		CloseServiceHandle(service_control_manager);
		return FALSE;
	}
	// add quotes for the case path contains a space (see CreateService doc)
	path[0] = path[len + 1] = TEXT('\"');
	path[len + 2] = 0;
	SC_HANDLE service = CreateService(service_control_manager, REGFLT_SERVICE_NAME,
		REGFLT_SERVICE_DISPLAY_NAME, SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
		SERVICE_ERROR_IGNORE, path, REGFLT_SERVICE_LOAD_ORDER_GROUP,
		0, TEXT("regflt\0"), 0, 0);
	if (service) {
		SERVICE_DESCRIPTION descr;
		descr.lpDescription = (LPTSTR)(REGFLT_SERVICE_DESCRIPTION);
		if (!ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &descr)) {
			printf("ChangeServiceConfig2 failed\n");
		}
		CloseServiceHandle(service);
		printf("Service installed successfully\n");
		ret = TRUE;
	}
	else if (GetLastError() == ERROR_SERVICE_EXISTS) {
		printf("Service already exists\n");
		ret = TRUE;
	}
	else {
		printf("Service not installed successfully, error %lu\n", GetLastError());
	}
	CloseServiceHandle(service_control_manager);
	return ret;
}

BOOL uninstall()
{
	BOOL ret = FALSE;

	UtilUnloadDriver(DRIVER_NAME);

	SC_HANDLE service_control_manager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);
	if (!service_control_manager) {
		printf("OpenSCManager failed\n");
		return FALSE;
	}
	SC_HANDLE service = OpenService(service_control_manager, REGFLT_SERVICE_NAME,
		SERVICE_QUERY_STATUS | DELETE);
	if (!service) {
		printf("OpenService failed\n");
		CloseServiceHandle(service_control_manager);
		return FALSE;
	}
	SERVICE_STATUS status;
	if (!QueryServiceStatus(service, &status)) {
		printf("QueryServiceStatus failed\n");
	}
	else if (status.dwCurrentState != SERVICE_STOPPED) {
		printf("Service is still running\n");
	}
	else if (DeleteService(service)) {
		printf("Service removed successfully\n");
		ret = TRUE;
	}
	else {
		switch (GetLastError()) {
		case ERROR_ACCESS_DENIED:
			printf("Access denied while trying to remove service\n");
			break;
		case ERROR_INVALID_HANDLE:
			printf("Handle invalid while trying to remove service\n");
			break;
		case ERROR_SERVICE_MARKED_FOR_DELETE:
			printf("Service already marked for deletion\n");
			break;
		}
	}
	CloseServiceHandle(service);
	CloseServiceHandle(service_control_manager);
	return ret;
}


DWORD WINAPI control_handler(DWORD control, DWORD event_type, LPVOID event_data,
	LPVOID context)
{
	VDService* s = (VDService *)(context);
	DWORD ret = NO_ERROR;

	UNREFERENCED_PARAMETER(event_type);
	UNREFERENCED_PARAMETER(event_data);

	switch (control) {
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		LOG_DEBUG("Stop service");
		running = FALSE;
		s->_status.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(s->_status_handle, &s->_status);
		if(hStopEvent)
			SetEvent(hStopEvent);
		break;
	case SERVICE_CONTROL_INTERROGATE:
		LOG_DEBUG("Interrogate service");
		SetServiceStatus(s->_status_handle, &s->_status);
		break;
	default:
		LOG_DEBUG("Unsupported control %lu", control);
		ret = ERROR_CALL_NOT_IMPLEMENTED;
	}
	return ret;
}


int _tmain(int argc, TCHAR* argv[])
{
	BOOL success = FALSE;

	if (argc > 1) {
		if (lstrcmpi(argv[1], TEXT("install")) == 0) {
			success = install();
		}
		else if (lstrcmpi(argv[1], TEXT("uninstall")) == 0) {
			success = uninstall();
		}
		else {
			printf("Use: regctrl install / uninstall\n");
		}
	}
	else {
		success = run();
	}
	
	return (success ? 0 : -1);
}

