#include "MacroMessageMapDemo.h"

DUI_BEGIN_MESSAGE_MAP(CDuiMainWnd, WindowImplBase)
	DUI_ON_MSGTYPE(DUI_MSGTYPE_CLICK, OnClick)
DUI_END_MESSAGE_MAP()

void CDuiMainWnd::OnClick(TNotifyUI& msg)
{
	if (msg.sType == _T("click"))
	{
		if (msg.pSender->GetName() == _T("closebtn"))
		{
			::DestroyWindow(m_hWnd);
			return;
		}
	}
}

/*
ֱ��������WindowImplBase���HandleMessage��OnDestroy����
*/
LRESULT CDuiMainWnd::OnDestroy(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	bHandled = FALSE;
	// �˳�����
	PostQuitMessage(0);
	return 0;
}
