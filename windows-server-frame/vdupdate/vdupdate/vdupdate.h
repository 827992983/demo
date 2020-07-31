#pragma once

#include "resource.h"

#define QDP_AGENT_WINCLASS_NAME  TEXT("VdupdateAgent")
#define QDP_TIMER_ID             1

enum { owner_none, owner_guest, owner_client };

typedef BOOL(WINAPI *PCLIPBOARD_OP)(HWND);

class VdupdateAgent
{
public:
	static VdupdateAgent* get();
	~VdupdateAgent();
	bool run();

private:
	VdupdateAgent();
	static LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);
	void cleanup();
	void DesktopMessageLoop();

private:
	static VdupdateAgent* instance;
	static bool m_bRunning;
	
	HWND m_hWnd;
	HANDLE m_hControlEvent;
	bool m_bSessionIsLocked;
	bool m_bLogonDesktop;
};
