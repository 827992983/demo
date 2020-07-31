#include "stdafx.h"
#include "vdupdate.h"
#include <wtsapi32.h>
#include <io.h>
#include <direct.h>
#include "logger.h"
#include "vdupdate_global.h"


#pragma warning( disable:4267)

HWND g_hWnd = NULL;

int CreateMultiFileList(char *strDirPath)
{
	if (strlen(strDirPath) > MAX_PATH)
	{
		return -1;
	}
	int ipathLength = strlen(strDirPath);
	int ileaveLength = 0;
	int iCreatedLength = 0;
	char szPathTemp[MAX_PATH] = { 0 };
	for (int i = 0; (NULL != strchr(strDirPath + iCreatedLength, '\\')); i++)
	{
		ileaveLength = strlen(strchr(strDirPath + iCreatedLength, '\\')) - 1;
		iCreatedLength = ipathLength - ileaveLength;
		strncpy(szPathTemp, strDirPath, iCreatedLength);
		_mkdir(szPathTemp);
	}

	if (iCreatedLength < ipathLength)
	{
		_mkdir(strDirPath);
	}

	return 0;
}

DWORD WINAPI WorkThreadProc(LPVOID lpParam)
{
	return 0;
}

DWORD WINAPI EventThreadProc(LPVOID lpParam)
{
	DWORD dwRet = 0;
	HWND hWnd = (HWND)lpParam;
	HANDLE hStopEvent = OpenEvent(SYNCHRONIZE, FALSE, AGENT_STOP_EVENT);
	if (hStopEvent == NULL)
	{
		LOG_ERROR("OpenEvent Error.Errno(%d)", GetLastError());
#ifdef IS_SERVICE
		::SendMessage(hWnd, WM_DESTROY, NULL, 0);
#else
		return 0;
#endif 
	}

	do {
		if (hStopEvent == NULL) {
			LOG_ERROR("hStopEvent is NULL.");
			break;
		}
		dwRet = WaitForSingleObject(hStopEvent, INFINITE);
		switch (dwRet) {
		case WAIT_OBJECT_0:
			LOG_ERROR("Receive qdp_service Stop Event.");
			::SendMessage(hWnd, WM_DESTROY, NULL, 0);
			//exit(0);
			break;
		case WAIT_TIMEOUT:
			LOG_ERROR("WaitForSingleObject for hStopEvent TimeOut.");
			break;
		default:
			LOG_ERROR("WaitForSingleObject for hStopEvent Default, Do Nothing.");
			break;
		}
	} while (1);
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

VdupdateAgent* VdupdateAgent::instance = NULL;
bool VdupdateAgent::m_bRunning = false;

VdupdateAgent::VdupdateAgent() 
	:m_hControlEvent(NULL)
{
	instance = this;
}

VdupdateAgent::~VdupdateAgent()
{
	instance = this;
}

VdupdateAgent* VdupdateAgent::get()
{
	if (!instance) {
		instance = new VdupdateAgent();
	}
	return instance;
}

void VdupdateAgent::cleanup()
{
	if (m_hControlEvent)
	{
		CloseHandle(m_hControlEvent);
		m_hControlEvent = NULL;
	}
}

LRESULT CALLBACK VdupdateAgent::WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int iRet = 0;
	BOOL bRet = FALSE;
	HANDLE hThread = NULL;
	VdupdateAgent* a = instance;

	switch (message) {
	case WM_CREATE:
		//create event thread, communication with service
		hThread = CreateThread(NULL, 0, EventThreadProc, hWnd, 0, NULL);
		if (hThread == NULL) {
			LOG_ERROR("Create Event Thread Error. Errorno(%d) ", GetLastError());
			exit(0);
		}
		CloseHandle(hThread);

		hThread = CreateThread(NULL, 0, WorkThreadProc, hWnd, 0, NULL);
		if (hThread == NULL) {
			LOG_ERROR("Create Work Thread Error. Errorno(%d) ", GetLastError());
			exit(0);
		}
		CloseHandle(hThread);
		break;
	case WM_TIMER:
		break;
	case WM_CHANGECBCHAIN:
		break;
	case WM_CLIPBOARDUPDATE:
	
	case WM_RENDERFORMAT:
		break;
	case WM_ENDSESSION:
		if (wParam) {
			LOG_DEBUG("Session ended");
		}
		break;
	case WM_WTSSESSION_CHANGE:
		if (wParam == WTS_SESSION_LOGON) {
		}
		else if (wParam == WTS_SESSION_LOCK) {
			a->m_bSessionIsLocked = true;
		}
		else if (wParam == WTS_SESSION_UNLOCK) {
			a->m_bSessionIsLocked = false;
		}
		break;
	case WM_DESTROY:
        PostQuitMessage(0);
		VdupdateAgent::m_bRunning = false;
        break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

void VdupdateAgent::DesktopMessageLoop()
{
	TCHAR desktop_name[MAX_PATH];
	HDESK hdesk;

	hdesk = OpenInputDesktop(0, FALSE, GENERIC_ALL);
	if (!hdesk) {
		LOG_ERROR("OpenInputDesktop() failed: %lu", GetLastError());
		VdupdateAgent::m_bRunning = false;
		return;
	}
#ifdef IS_SERVICE
	if (!SetThreadDesktop(hdesk)) {
		LOG_ERROR("SetThreadDesktop failed %lu", GetLastError());
		CloseDesktop(hdesk);
		VdupdateAgent::m_bRunning = false;
		return;
	}
#endif
	if (GetUserObjectInformation(hdesk, UOI_NAME, desktop_name, sizeof(desktop_name), NULL)) {
		LOG_ERROR("Desktop: %S", desktop_name);
	}
	else {
		LOG_ERROR("GetUserObjectInformation failed %lu", GetLastError());
	}
	CloseDesktop(hdesk);

	// loading the display settings for the current session's logged on user only
	// after 1) we receive logon event, and 2) the desktop switched from Winlogon
	if (_tcscmp(desktop_name, TEXT("Winlogon")) == 0)
	{
		m_bLogonDesktop = true;
	}
	else 
	{
		m_bLogonDesktop = false;
	}

	m_hWnd = CreateWindow(QDP_AGENT_WINCLASS_NAME, NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
	if (!m_hWnd) {
		LOG_ERROR("CreateWindow() failed: %lu", GetLastError());
		VdupdateAgent::m_bRunning = false;
		return;
	}

	if (!WTSRegisterSessionNotification(m_hWnd, NOTIFY_FOR_ALL_SESSIONS)) {
		LOG_ERROR("WTSRegisterSessionNotification() failed: %lu", GetLastError());
	}


	while (VdupdateAgent::m_bRunning) {
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	WTSUnRegisterSessionNotification(m_hWnd);
	DestroyWindow(m_hWnd);
}

bool VdupdateAgent::run()
{
	DWORD session_id;
	WNDCLASS wcls;

	if (!ProcessIdToSessionId(GetCurrentProcessId(), &session_id)) {
		LOG_ERROR("ProcessIdToSessionId failed %lu", GetLastError());
		return false;
	}
	LOG_INFO("***VdupdateAgent started in session %lu***", session_id);

	if (!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
		LOG_ERROR("SetPriorityClass failed %lu", GetLastError());
	}
	if (!SetProcessShutdownParameters(0x100, 0)) {
		LOG_ERROR("SetProcessShutdownParameters failed %lu", GetLastError());
	}

	m_hControlEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!m_hControlEvent) {
		LOG_ERROR("CreateEvent() failed: %lu", GetLastError());
		cleanup();
		return false;
	}

	memset(&wcls, 0, sizeof(wcls));
	wcls.lpfnWndProc = &VdupdateAgent::WndProc;
	wcls.lpszClassName = QDP_AGENT_WINCLASS_NAME;
	if (!RegisterClass(&wcls)) {
		LOG_ERROR("RegisterClass() failed: %lu", GetLastError());
		return false;
	}
	
	VdupdateAgent::m_bRunning = true;
	while (VdupdateAgent::m_bRunning) {
		DesktopMessageLoop();
	}
	LOG_ERROR("Agent stopped");
	return true;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	if (_access(DEFAULT_LOG_DIR_PATH, 0) == -1)
	{
		int ret = CreateMultiFileList(DEFAULT_LOG_DIR_PATH);

		if (ret == 0)
		{
			LOG_DEBUG("make dir success");
		}
		else
		{
			LOG_DEBUG("make dir failed");
		}
	}

	log_init(DEFAULT_LOG_FILE_PATH);

	VdupdateAgent* agent = VdupdateAgent::get();
	agent->run();
	delete agent;

	log_cleanup();
	return 0;
}
