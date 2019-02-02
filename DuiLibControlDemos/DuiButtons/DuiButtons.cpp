#include "DuiButtons.h"
#include "DuiMessageBox.h"

DUI_BEGIN_MESSAGE_MAP(CDuiMainWnd, WindowImplBase)
	DUI_ON_MSGTYPE(DUI_MSGTYPE_CLICK, OnClick)
DUI_END_MESSAGE_MAP()

void CDuiMainWnd::OnClick(TNotifyUI& msg)
{
	if (msg.sType == _T("click"))
	{
		if (msg.pSender->GetName() == _T("closebtn"))
		{
			//::MessageBox(NULL, _T("Duilib旗舰版"), _T("确定退出duidemo演示程序？"), MB_OK);
			CDuiMessageBox::MessageBox(m_hWnd, _T("演示程序"), _T("确定退出演示程序？"));
			DestroyWindow(m_hWnd);
			return;
		}
		if (msg.pSender->GetName() == _T("minbtn"))
		{
			SendMessage(WM_SYSCOMMAND, SC_MINIMIZE, 0);
			return;
		}
		if (msg.pSender->GetName() == _T("maxbtn"))
		{
			SendMessage(WM_SYSCOMMAND, SC_MAXIMIZE, 0);
			return;
		}
		if (msg.pSender->GetName() == _T("restorebtn"))
		{
			SendMessage(WM_SYSCOMMAND, SC_RESTORE, 0);
			return;
		}
	}
}

LRESULT CDuiMainWnd::OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& bHandled)
{
	bHandled = FALSE;
	// 退出程序
	PostQuitMessage(0);
	return 0;
}