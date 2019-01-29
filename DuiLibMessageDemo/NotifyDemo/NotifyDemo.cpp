#include "NotifyDemo.h"

/*
消息处理函数
*/
void CDuiMainWnd::Notify(TNotifyUI& msg)
{
	if (msg.sType == _T("click"))
	{
		if (msg.pSender->GetName() == _T("closebtn"))
		{
			::DestroyWindow(m_hWnd); //Close(0);
			return;
		}
	}
}

/*
直接重载了WindowImplBase类的HandleMessage的OnDestroy函数
*/
LRESULT CDuiMainWnd::OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& bHandled)
{
	bHandled = FALSE;
	// 退出程序
	PostQuitMessage(0);
	return 0;
}

