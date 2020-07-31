/*
Copyright (C) 2009 Red Hat, Inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of
the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include <winternl.h>
#include <wtsapi32.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <queue>
#include <tchar.h>
#include "logger.h"
#include "win_common.h"
#include "../vdupdate/vdupdate_global.h"

//#define DEBUG_SERVICE

#define SERVICE_DISPLAY_NAME TEXT("QingCloud Update Service")
#define SERVICE_NAME         TEXT("vdupdate_service")
#define SERVICE_DESC	TEXT("QingCloud Update Service.")

#define SERVICE_LOAD_ORDER_GROUP TEXT("Pointer Port")
#define AGENT_PATH           TEXT("%s\\vdupdate.exe")
#define AGENT_TIMEOUT        10000											//wait event timeout
#define AGENT_MAX_RESTARTS   10												//agent program restart retry num
#define AGENT_RESTART_INTERVAL 3000											//agent program restart retry interval time 
#define AGENT_RESTART_COUNT_RESET_INTERVAL 60000							//
#define WINLOGON_FILENAME       TEXT("winlogon.exe")							//winlogon.exe define
#define CREATE_PROC_MAX_RETRIES 10												//agent program start retry num 
#define CREATE_PROC_INTERVAL_MS 500												//agent program start retry interval time

// This enum simplifies WaitForMultipleEvents for static
// events, that is handles that are guranteed non NULL.
// It doesn't include:
// Agent handle - this can be 1 or 0 (NULL or not), so it is also added at
//  the end of VdupdateService::_events
enum {
	EVENT_CONTROL = 0,
	STATIC_EVENTS_COUNT // Must be last
};

enum {
	CONTROL_IDLE = 0,
	CONTROL_STOP,
	CONTROL_RESTART_AGENT,
};

typedef std::queue<int> VdupdateControlQueue;

class VdupdateService {
public:
	static bool run();
	static bool install();
	static bool uninstall();

private:
	VdupdateService();
	~VdupdateService();
	bool execute();
	void stop();
	static DWORD WINAPI control_handler(DWORD control, DWORD event_type,
		LPVOID event_data, LPVOID context);
	static VOID WINAPI main(DWORD argc, TCHAR * argv[]);
	void set_control_event(int control_command);
	void handle_control_event();
	bool restart_agent(bool normal_restart);
	bool launch_agent();
	bool kill_agent();
	unsigned fill_agent_event() {
		_ASSERTE(_events);
		if (_agent_process) {
			_events[_events_count - 1] = _agent_process;
			return _events_count;
		}
		else {
			return _events_count - 1;
		}
	}
	bool agent_alive() const { return _agent_process != NULL; }
private:
	SERVICE_STATUS _status;
	SERVICE_STATUS_HANDLE _status_handle;
	HANDLE _agent_process;
	HANDLE _control_event;
	HANDLE _agent_stop_event;
	HANDLE* _events;
	TCHAR _agent_path[MAX_PATH];
	VdupdateControlQueue _control_queue;
	mutex_t _control_mutex;
	mutex_t _agent_mutex;
	uint32_t _connection_id;
	DWORD _session_id;
	DWORD _last_agent_restart_time;
	int _agent_restarts;
	int _system_version;
	bool _running;
	unsigned _events_count;
};

VdupdateService::VdupdateService()
	: _status_handle(0)
	, _agent_process(NULL)
	, _events(NULL)
	, _connection_id(0)
	, _session_id(0)
	, _last_agent_restart_time(0)
	, _agent_restarts(0)
	, _running(false)
	, _events_count(0)
{
	_system_version = supported_system_version();
	_control_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	_agent_stop_event = CreateEvent(NULL, FALSE, FALSE, AGENT_STOP_EVENT);
	_agent_path[0] = wchar_t('\0');
}

VdupdateService::~VdupdateService()
{
	CloseHandle(_agent_stop_event);
	CloseHandle(_control_event);
	delete[] _events;
}

bool VdupdateService::run()
{
#ifndef DEBUG_SERVICE
	SERVICE_TABLE_ENTRY service_table[] = {
		{ const_cast<LPTSTR>(SERVICE_NAME), main },{ 0, 0 } };
	return !!StartServiceCtrlDispatcher(service_table);
#else
	main(0, NULL);
	return true;
#endif
}

bool VdupdateService::install()
{
	bool ret = false;

	SC_HANDLE service_control_manager = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
	if (!service_control_manager) {
		printf("OpenSCManager failed\n");
		return false;
	}
	TCHAR path[_MAX_PATH + 2];
	DWORD len = GetModuleFileName(0, path + 1, _MAX_PATH);
	if (len == 0 || len == _MAX_PATH) {
		printf("GetModuleFileName failed\n");
		CloseServiceHandle(service_control_manager);
		return false;
	}
	// add quotes for the case path contains a space (see CreateService doc)
	path[0] = path[len + 1] = TEXT('\"');
	path[len + 2] = 0;
	SC_HANDLE service = CreateService(service_control_manager, SERVICE_NAME,
		SERVICE_DISPLAY_NAME, SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
		SERVICE_ERROR_IGNORE, path, SERVICE_LOAD_ORDER_GROUP,
		0, 0, 0, 0);
	if (service) {
		SERVICE_DESCRIPTION descr;
		descr.lpDescription = const_cast<LPTSTR>(SERVICE_DESC);
		if (!ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &descr)) {
			printf("ChangeServiceConfig2 failed\n");
		}
		CloseServiceHandle(service);
		printf("Service installed successfully\n");
		ret = true;
	}
	else if (GetLastError() == ERROR_SERVICE_EXISTS) {
		printf("Service already exists\n");
		ret = true;
	}
	else {
		printf("Service not installed successfully, error %lu\n", GetLastError());
	}
	CloseServiceHandle(service_control_manager);
	return ret;
}

bool VdupdateService::uninstall()
{
	bool ret = false;

	SC_HANDLE service_control_manager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);
	if (!service_control_manager) {
		printf("OpenSCManager failed\n");
		return false;
	}
	SC_HANDLE service = OpenService(service_control_manager, SERVICE_NAME,
		SERVICE_QUERY_STATUS | DELETE);
	if (!service) {
		printf("OpenService failed\n");
		CloseServiceHandle(service_control_manager);
		return false;
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
		ret = true;
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

static const char* const session_events[] = {
	"INVALID", "CONNECT", "DISCONNECT", "REMOTE_CONNECT", "REMOTE_DISCONNECT", "LOGON", "LOGOFF",
	"LOCK", "UNLOCK", "REMOTE_CONTROL"
};

void VdupdateService::set_control_event(int control_command)
{
	MutexLocker lock(_control_mutex);
	_control_queue.push(control_command);
	if (_control_event && !SetEvent(_control_event)) {
		LOG_ERROR("SetEvent() failed: %lu", GetLastError());
	}
}

void VdupdateService::handle_control_event()
{
	MutexLocker lock(_control_mutex);
	while (_control_queue.size()) {
		int control_command = _control_queue.front();
		_control_queue.pop();
		switch (control_command) {
		case CONTROL_STOP:
			_running = false;
			break;
		case CONTROL_RESTART_AGENT:
			_running = restart_agent(true);
			break;
		default:
			LOG_ERROR("Unsupported control command %u", control_command);
		}
	}
}

DWORD WINAPI VdupdateService::control_handler(DWORD control, DWORD event_type, LPVOID event_data,
	LPVOID context)
{
	VdupdateService* s = static_cast<VdupdateService *>(context);
	DWORD ret = NO_ERROR;

	_ASSERTE(s);
	switch (control) {
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		LOG_ERROR("Stop service");
		s->_status.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(s->_status_handle, &s->_status);
		s->stop();
		break;
	case SERVICE_CONTROL_INTERROGATE:
		LOG_ERROR("Interrogate service");
		SetServiceStatus(s->_status_handle, &s->_status);
		break;
	case SERVICE_CONTROL_SESSIONCHANGE: {
		DWORD session_id = ((WTSSESSION_NOTIFICATION*)event_data)->dwSessionId;
		LOG_ERROR("Session %lu %s", session_id,
			event_type < ARRAYSIZE(session_events) ? session_events[event_type] : "unknown");
		SetServiceStatus(s->_status_handle, &s->_status);
		if (event_type == WTS_CONSOLE_CONNECT) {
			s->_session_id = session_id;
			s->set_control_event(CONTROL_RESTART_AGENT);
		}
		break;
	}
	default:
		LOG_ERROR("Unsupported control %lu", control);
		ret = ERROR_CALL_NOT_IMPLEMENTED;
	}
	return ret;
}

#define VDSERVICE_ACCEPTED_CONTROLS \
    (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE)

VOID WINAPI VdupdateService::main(DWORD argc, TCHAR* argv[])
{
	VdupdateService* s = new VdupdateService;
	SERVICE_STATUS* status;
	TCHAR path[MAX_PATH];
	TCHAR* slash;

	_ASSERTE(s);
	if (GetModuleFileName(NULL, path, MAX_PATH) && (slash = _tcsrchr(path, TCHAR('\\')))) {
		*slash = TCHAR('\0');
		_stprintf_s(s->_agent_path, MAX_PATH, AGENT_PATH, path);
		LOG_DEBUG("s->_agent_path = %s", s->_agent_path);
	}
	LOG_DEBUG("***Service started***");
	if (!SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS)) {
		LOG_ERROR("SetPriorityClass failed %lu", GetLastError());
	}
	status = &s->_status;
	status->dwServiceType = SERVICE_WIN32;
	status->dwCurrentState = SERVICE_STOPPED;
	status->dwControlsAccepted = 0;
	status->dwWin32ExitCode = NO_ERROR;
	status->dwServiceSpecificExitCode = NO_ERROR;
	status->dwCheckPoint = 0;
	status->dwWaitHint = 0;
#ifndef  DEBUG_SERVICE
	s->_status_handle = RegisterServiceCtrlHandlerEx(SERVICE_NAME, &VdupdateService::control_handler,
		s);
	if (!s->_status_handle) {
		LOG_ERROR("RegisterServiceCtrlHandler failed\n");
		return;
	}

	// service is starting
	status->dwCurrentState = SERVICE_START_PENDING;
	SetServiceStatus(s->_status_handle, status);

	// service running
	status->dwControlsAccepted |= VDSERVICE_ACCEPTED_CONTROLS;
	status->dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(s->_status_handle, status);
#endif //DEBUG_SERVICE

	s->_running = true;
	s->execute();

#ifndef  DEBUG_SERVICE
	// service was stopped
	status->dwCurrentState = SERVICE_STOP_PENDING;
	SetServiceStatus(s->_status_handle, status);

	// service is stopped
	status->dwControlsAccepted &= ~VDSERVICE_ACCEPTED_CONTROLS;
	status->dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(s->_status_handle, status);
#endif //DEBUG_SERVICE
	LOG_ERROR("***Service stopped***");
	delete s;
}

bool VdupdateService::execute()
{
	INT* con_state = NULL;
	bool con_state_active = false;
	DWORD bytes;

	_session_id = WTSGetActiveConsoleSessionId();
	if (_session_id == 0xFFFFFFFF) {
		LOG_ERROR("WTSGetActiveConsoleSessionId() failed");
		_running = false;
	}
	LOG_ERROR("Active console session id: %lu", _session_id);
	if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, _session_id,
		WTSConnectState, (LPTSTR *)&con_state, &bytes)) {
		LOG_ERROR("Connect state: %d", *con_state);
		con_state_active = (*con_state == WTSActive);
		WTSFreeMemory(con_state);
	}
	if (_running && !launch_agent()) {
		// In case of agent launch failure: if connection state is not active(*), wait for agent
		// launch on the next session connection. Otherwise, the service is stopped.
		// (*) The failure was due to system startup timings and logon settings, causing the first
		// agent instance lifetime (before session connect) to be too short to connect the service.
		_running = !con_state_active && (GetLastError() != ERROR_FILE_NOT_FOUND);
		if (_running) {
			LOG_ERROR("Failed launching vdagent instance, waiting for session connection");
		}
		while (_running) {
			if (WaitForSingleObject(_control_event, INFINITE) == WAIT_OBJECT_0) {
				handle_control_event();
			}
		}
	}
	if (!_running) {
		return false;
	}
	_events_count = STATIC_EVENTS_COUNT + 1 /*for agent*/;
	_events = new HANDLE[_events_count];
	ZeroMemory(_events, _events_count);
	_events[EVENT_CONTROL] = _control_event;
	while (_running) {
		unsigned actual_events = fill_agent_event();
		DWORD wait_ret = WaitForMultipleObjects(actual_events, _events, FALSE, INFINITE);
		switch (wait_ret) {
		case WAIT_OBJECT_0 + EVENT_CONTROL:
			handle_control_event();
			break;
		case WAIT_OBJECT_0 + STATIC_EVENTS_COUNT:
			LOG_ERROR("Agent killed");
			if (_system_version == SYS_VER_WIN_XP_CLASS) {
				restart_agent(false);
			}
			else if (_system_version == SYS_VER_WIN_7_CLASS) {
				kill_agent();
				// Assume agent was killed due to console disconnect, and wait for agent
				// normal restart due to console connect. If the agent is not alive yet,
				// it was killed manually (or crashed), so let's restart it.
				if (WaitForSingleObject(_control_event, AGENT_RESTART_INTERVAL) ==
					WAIT_OBJECT_0) {
					handle_control_event();
				}
				if (_running && !agent_alive()) {
					restart_agent(false);
				}
			}
			break;
		case WAIT_TIMEOUT:
			break;
		default:
			LOG_ERROR("WaitForMultipleObjects failed %lu", GetLastError());
			_running = false;
		}
	}
	kill_agent();
	return true;
}

static DWORD64 marshall_string(LPCWSTR str, DWORD max_size, LPBYTE* next_buf, DWORD* used_bytes)
{
	DWORD offset = *used_bytes;

	if (!str) {
		return 0;
	}
	DWORD len = (DWORD)(wcslen(str) + 1) * sizeof(WCHAR);
	if (*used_bytes + len > max_size) {
		return 0;
	}
	memmove(*next_buf, str, len);
	*used_bytes += len;
	*next_buf += len;
	return offset;
}

typedef struct CreateProcessParams {
	DWORD size;
	DWORD process_id;
	BOOL use_default_token;
	HANDLE token;
	LPWSTR application_name;
	LPWSTR command_line;
	SECURITY_ATTRIBUTES process_attributes;
	SECURITY_ATTRIBUTES thread_attributes;
	BOOL inherit_handles;
	DWORD creation_flags;
	LPVOID environment;
	LPWSTR current_directory;
	STARTUPINFOW startup_info;
	PROCESS_INFORMATION process_information;
	BYTE data[0x2000];
} CreateProcessParams;

typedef struct CreateProcessRet {
	DWORD size;
	BOOL ret_value;
	DWORD last_error;
	PROCESS_INFORMATION process_information;
} CreateProcessRet;

static BOOL
create_session_process_as_user(IN DWORD session_id, IN BOOL use_default_token, IN HANDLE token,
	IN LPCWSTR application_name, IN LPWSTR command_line,
	IN LPSECURITY_ATTRIBUTES process_attributes,
	IN LPSECURITY_ATTRIBUTES thread_attributes,
	IN BOOL inherit_handles, IN DWORD creation_flags,
	IN LPVOID environment, IN LPCWSTR current_directory,
	IN LPSTARTUPINFOW startup_info,
	OUT LPPROCESS_INFORMATION process_information)
{
	WCHAR win_sta_path[MAX_PATH];
	HINSTANCE win_sta_handle;
	WCHAR pipe_name[MAX_PATH] = L"";
	DWORD pipe_name_len;
	BOOL got_pipe_name = FALSE;
	HANDLE named_pipe;
	CreateProcessRet proc_ret;
	CreateProcessParams proc_params;
	LPBYTE buffer = (LPBYTE)proc_params.data;
	DWORD max_size = sizeof(proc_params);
	DWORD bytes_used = offsetof(CreateProcessParams, data);
	DWORD bytes_written;
	DWORD bytes_read;
	DWORD env_len = 0;
	BOOL ret = FALSE;

	GetSystemDirectoryW(win_sta_path, MAX_PATH);
	lstrcatW(win_sta_path, L"\\winsta.dll");
	win_sta_handle = LoadLibrary(win_sta_path);
	if (win_sta_handle) {
		PWINSTATIONQUERYINFORMATIONW win_sta_query_func =
			(PWINSTATIONQUERYINFORMATIONW)GetProcAddress(win_sta_handle,
				"WinStationQueryInformationW");
		if (win_sta_query_func) {
			got_pipe_name = win_sta_query_func(0, session_id, (WINSTATIONINFOCLASS)0x21,
				pipe_name, sizeof(pipe_name), &pipe_name_len);
		}
		FreeLibrary(win_sta_handle);
	}
	if (!got_pipe_name || pipe_name[0] == '\0') {
		swprintf_s(pipe_name, MAX_PATH, L"\\\\.\\Pipe\\TerminalServer\\SystemExecSrvr\\%d",
			session_id);
	}

	do {
		named_pipe = CreateFile(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
			0, 0);
		if (named_pipe == INVALID_HANDLE_VALUE) {
			if (GetLastError() == ERROR_PIPE_BUSY) {
				if (!WaitNamedPipe(pipe_name, 3000)) {
					return FALSE;
				}
			}
			else {
				return FALSE;
			}
		}
	} while (named_pipe == INVALID_HANDLE_VALUE);

	memset(&proc_params, 0, sizeof(proc_params));
	proc_params.process_id = GetCurrentProcessId();
	proc_params.use_default_token = use_default_token;
	proc_params.token = token;
	proc_params.application_name = (LPWSTR)marshall_string(application_name, max_size, &buffer,
		&bytes_used);
	proc_params.command_line = (LPWSTR)marshall_string(command_line, max_size, &buffer,
		&bytes_used);
	if (process_attributes) {
		proc_params.process_attributes = *process_attributes;
	}
	if (thread_attributes) {
		proc_params.thread_attributes = *thread_attributes;
	}
	proc_params.inherit_handles = inherit_handles;
	proc_params.creation_flags = creation_flags;
	proc_params.current_directory = (LPWSTR)marshall_string(current_directory, max_size,
		&buffer, &bytes_used);
	if (startup_info) {
		proc_params.startup_info = *startup_info;
		proc_params.startup_info.lpDesktop = (LPWSTR)marshall_string(startup_info->lpDesktop,
			max_size, &buffer,
			&bytes_used);
		proc_params.startup_info.lpTitle = (LPWSTR)marshall_string(startup_info->lpTitle,
			max_size, &buffer, &bytes_used);
	}
	if (environment) {
		if (creation_flags & CREATE_UNICODE_ENVIRONMENT) {
			while ((env_len + bytes_used <= max_size)) {
				if (((LPWSTR)environment)[env_len / 2] == '\0' &&
					((LPWSTR)environment)[env_len / 2 + 1] == '\0') {
					env_len += 2 * sizeof(WCHAR);
					break;
				}
				env_len += sizeof(WCHAR);
			}
		}
		else {
			while (env_len + bytes_used <= max_size) {
				if (((LPSTR)environment)[env_len] == '\0' &&
					((LPSTR)environment)[env_len + 1] == '\0') {
					env_len += 2;
					break;
				}
				env_len++;
			}
		}
		if (env_len + bytes_used <= max_size) {
			memmove(buffer, environment, env_len);
			proc_params.environment = (LPVOID)(UINT64)bytes_used;
			buffer += env_len;
			bytes_used += env_len;
		}
		else {
			proc_params.environment = NULL;
		}
	}
	else {
		proc_params.environment = NULL;
	}
	proc_params.size = bytes_used;

	if (WriteFile(named_pipe, &proc_params, proc_params.size, &bytes_written, NULL) &&
		ReadFile(named_pipe, &proc_ret, sizeof(proc_ret), &bytes_read, NULL)) {
		ret = proc_ret.ret_value;
		if (ret) {
			*process_information = proc_ret.process_information;
			if (process_information->hProcess == 0) {
				process_information->hProcess = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE,
					process_information->dwProcessId);
				if (!process_information->hProcess) {
					LOG_ERROR("OpenProcess() failed %lu", GetLastError());
				}
			}
		}
		else {
			SetLastError(proc_ret.last_error);
		}
	}
	else {
		ret = FALSE;
	}
	CloseHandle(named_pipe);
	return ret;
}

static BOOL
create_process_as_user(IN DWORD session_id, IN LPCWSTR application_name,
	IN LPWSTR command_line, IN LPSECURITY_ATTRIBUTES process_attributes,
	IN LPSECURITY_ATTRIBUTES thread_attributes, IN BOOL inherit_handles,
	IN DWORD creation_flags, IN LPVOID environment,
	IN LPCWSTR current_directory, IN LPSTARTUPINFOW startup_info,
	OUT LPPROCESS_INFORMATION process_information)
{
	PROCESSENTRY32 proc_entry;
	DWORD winlogon_pid = 0;
	HANDLE winlogon_proc;
	HANDLE token = NULL;
	HANDLE token_dup;
	BOOL ret = FALSE;

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateToolhelp32Snapshot() failed %lu", GetLastError());
		return false;
	}
	ZeroMemory(&proc_entry, sizeof(proc_entry));
	proc_entry.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(snap, &proc_entry)) {
		LOG_ERROR("Process32First() failed %lu", GetLastError());
		CloseHandle(snap);
		return false;
	}
	do {
		if (_tcsicmp(proc_entry.szExeFile, WINLOGON_FILENAME) == 0) {
			DWORD winlogon_session_id = 0;
			if (ProcessIdToSessionId(proc_entry.th32ProcessID, &winlogon_session_id) &&
				winlogon_session_id == session_id) {
				winlogon_pid = proc_entry.th32ProcessID;
				break;
			}
		}
	} while (Process32Next(snap, &proc_entry));
	CloseHandle(snap);
	if (winlogon_pid == 0) {
		LOG_ERROR("Winlogon not found");
		return false;
	}
	winlogon_proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogon_pid);
	if (!winlogon_proc) {
		LOG_ERROR("OpenProcess() failed %lu", GetLastError());
		return false;
	}
	ret = OpenProcessToken(winlogon_proc, TOKEN_DUPLICATE, &token);
	CloseHandle(winlogon_proc);
	if (!ret) {
		LOG_ERROR("OpenProcessToken() failed %lu", GetLastError());
		return false;
	}
	ret = DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary,
		&token_dup);
	CloseHandle(token);
	if (!ret) {
		LOG_ERROR("DuplicateTokenEx() failed %lu", GetLastError());
		return false;
	}
	ret = CreateProcessAsUser(token_dup, application_name, command_line, process_attributes,
		thread_attributes, inherit_handles, creation_flags, environment,
		current_directory, startup_info, process_information);
	CloseHandle(token_dup);
	return ret;
}

bool VdupdateService::launch_agent()
{
	STARTUPINFO startup_info;
	BOOL ret = FALSE;
	PROCESS_INFORMATION agent_proc_info = {};

	ZeroMemory(&startup_info, sizeof(startup_info));
	startup_info.cb = sizeof(startup_info);
	startup_info.lpDesktop = const_cast<LPTSTR>(TEXT("Winsta0\\winlogon"));
	_agent_process = NULL;
	if (_system_version == SYS_VER_WIN_XP_CLASS) {
		if (_session_id == 0) {
			ret = CreateProcess(_agent_path, _agent_path, NULL, NULL, FALSE, 0, NULL, NULL,
				&startup_info, &agent_proc_info);
		}
		else {
			for (int i = 0; i < CREATE_PROC_MAX_RETRIES; i++) {
				ret = create_session_process_as_user(_session_id, TRUE, NULL, NULL, _agent_path,
					NULL, NULL, FALSE, 0, NULL, NULL,
					&startup_info, &agent_proc_info);
				if (ret) {
					LOG_ERROR("create_session_process_as_user #%d", i);
					break;
				}
				Sleep(CREATE_PROC_INTERVAL_MS);
			}
		}
	}
	else if (_system_version == SYS_VER_WIN_7_CLASS) {
		startup_info.lpDesktop = const_cast<LPTSTR>(TEXT("Winsta0\\default"));
		ret = create_process_as_user(_session_id, _agent_path, _agent_path, NULL, NULL, FALSE, 0,
			NULL, NULL, &startup_info, &agent_proc_info);
	}
	else {
		LOG_ERROR("Not supported in this system version");
		return false;
	}
	if (!ret) {
		LOG_ERROR("CreateProcess() failed: %lu", GetLastError());
		return false;
	}
	CloseHandle(agent_proc_info.hThread);
	_agent_process = agent_proc_info.hProcess;
	return true;
}

bool VdupdateService::kill_agent()
{
	DWORD exit_code = 0;
	DWORD wait_ret;
	HANDLE proc_handle;
	bool ret = true;

	if (!agent_alive()) {
		return true;
	}
	proc_handle = _agent_process;
	_agent_process = NULL;
	SetEvent(_agent_stop_event);
	if (GetProcessId(proc_handle)) {
		wait_ret = WaitForSingleObject(proc_handle, AGENT_TIMEOUT);
		switch (wait_ret) {
		case WAIT_OBJECT_0:
			if (GetExitCodeProcess(proc_handle, &exit_code)) {
				ret = (exit_code != STILL_ACTIVE);
			}
			else {
				LOG_ERROR("GetExitCodeProcess() failed: %lu", GetLastError());
			}
			break;
		case WAIT_TIMEOUT:
			LOG_ERROR("Wait timeout");
			ret = false;
			break;
		case WAIT_FAILED:
		default:
			LOG_ERROR("WaitForSingleObject() failed: %lu", GetLastError());
			break;
		}
	}
	ResetEvent(_agent_stop_event);
	CloseHandle(proc_handle);
	return ret;
}

bool VdupdateService::restart_agent(bool normal_restart)
{
	DWORD time = GetTickCount();
	bool ret = true;

	MutexLocker lock(_agent_mutex);
	if (!normal_restart && ++_agent_restarts > AGENT_MAX_RESTARTS) {
		LOG_ERROR("Agent restarted too many times");
		ret = false;
		stop();
	}
	if (ret && kill_agent() && launch_agent()) {
		if (time - _last_agent_restart_time > AGENT_RESTART_COUNT_RESET_INTERVAL) {
			_agent_restarts = 0;
		}
		_last_agent_restart_time = time;
		ret = true;
	}
	return ret;
}

void VdupdateService::stop()
{
	LOG_ERROR("Service stopped");
	set_control_event(CONTROL_STOP);
}

#ifdef __GNUC__
#undef _tmain
#ifdef UNICODE
int _tmain(int argc, TCHAR* argv[]);
int main(void)
{
	int argc;
	TCHAR** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	return _tmain(argc, argv);
}
#else
#define _tmain main
#endif
#endif

int _tmain(int argc, TCHAR* argv[])
{
	bool success = false;

	log_init(SERVICE_LOG_PATH);
	log_level = LEVEL_ERROR;
	if (!supported_system_version()) {
		printf("vdservice is not supported in this system version\n");
		return -1;
	}
	if (argc > 1) {
		if (lstrcmpi(argv[1], TEXT("install")) == 0) {
			success = VdupdateService::install();
		}
		else if (lstrcmpi(argv[1], TEXT("uninstall")) == 0) {
			success = VdupdateService::uninstall();
		}
		else {
			printf("Use: vdservice install / uninstall\n");
		}
	}
	else {
		success = VdupdateService::run();
	}

	log_cleanup();
	return (success ? 0 : -1);
}
