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
直接重载了WindowImplBase类的HandleMessage的OnDestroy函数
*/
LRESULT CDuiMainWnd::OnDestroy(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	bHandled = FALSE;
	// 退出程序
	PostQuitMessage(0);
	return 0;
}
