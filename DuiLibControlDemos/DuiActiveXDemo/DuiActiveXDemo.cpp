#include "DuiActiveXDemo.h"

DUI_BEGIN_MESSAGE_MAP(CDuiMainWnd, WindowImplBase)
	DUI_ON_MSGTYPE(DUI_MSGTYPE_CLICK, OnClick)
DUI_END_MESSAGE_MAP()

void CDuiMainWnd::InitWindow()
{
	// ActiveX控件使用
	CActiveXUI* pActiveXUI = static_cast<CActiveXUI*>(m_pm.FindControl(_T("activex_demo")));
	if (pActiveXUI)
	{
		IWebBrowser2* pWebBrowser = NULL;
		pActiveXUI->SetDelayCreate(false); // 相当于界面设计器里的DelayCreate 属性改为FALSE，在duilib 自带的FlashDemo 里可以看到此属性为TRUE
		pActiveXUI->CreateControl(CLSID_WebBrowser); // 相当于界面设计器里的Clsid 属性里填入{ 8856F961 - 340A - 11D0 - A96B - 00C04FD705A2 }，建议用CLSID_WebBrowser，如果想看相应的值，请见<ExDisp.h>
		pActiveXUI->GetControl(IID_IWebBrowser2, (void**)&pWebBrowser);
		if (pWebBrowser != NULL)
		{
			pWebBrowser->Navigate(_T("http://www.baidu.com/"), NULL, NULL, NULL, NULL); //打开网址
			pWebBrowser->Release();
		}
	}
}

void CDuiMainWnd::OnClick(TNotifyUI& msg)
{
	if (msg.sType == _T("click"))
	{
		if (msg.pSender->GetName() == _T("closebtn"))
		{
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