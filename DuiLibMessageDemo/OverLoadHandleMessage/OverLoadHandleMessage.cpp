#include "OverLoadHandleMessage.h"


void CDuiMainWnd::Notify(TNotifyUI& msg)
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
LRESULT CDuiMainWnd::HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam)//自绘标题栏
{
	LRESULT lRes = 0;
	if (uMsg == WM_CREATE)
	{
		__super::HandleMessage(uMsg, wParam, lParam);
		//TODO：过滤WM_CREATE消息后，希望做的其他额外操作

		return lRes;
	}
	// TODO：过滤WM_DESTROY，在窗口销毁后，退出程序
	else if (uMsg == WM_DESTROY)
	{
		::PostQuitMessage(0L);
		return 0;
	}

	return __super::HandleMessage(uMsg, wParam, lParam);
}