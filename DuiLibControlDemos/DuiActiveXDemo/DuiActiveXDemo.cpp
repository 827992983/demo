#include "DuiActiveXDemo.h"

DUI_BEGIN_MESSAGE_MAP(CDuiMainWnd, WindowImplBase)
	DUI_ON_MSGTYPE(DUI_MSGTYPE_CLICK, OnClick)
DUI_END_MESSAGE_MAP()

void CDuiMainWnd::InitWindow()
{
	// ActiveX�ؼ�ʹ��
	CActiveXUI* pActiveXUI = static_cast<CActiveXUI*>(m_pm.FindControl(_T("activex_demo")));
	if (pActiveXUI)
	{
		IWebBrowser2* pWebBrowser = NULL;
		pActiveXUI->SetDelayCreate(false); // �൱�ڽ�����������DelayCreate ���Ը�ΪFALSE����duilib �Դ���FlashDemo ����Կ���������ΪTRUE
		pActiveXUI->CreateControl(CLSID_WebBrowser); // �൱�ڽ�����������Clsid ����������{ 8856F961 - 340A - 11D0 - A96B - 00C04FD705A2 }��������CLSID_WebBrowser������뿴��Ӧ��ֵ�����<ExDisp.h>
		pActiveXUI->GetControl(IID_IWebBrowser2, (void**)&pWebBrowser);
		if (pWebBrowser != NULL)
		{
			pWebBrowser->Navigate(_T("http://www.baidu.com/"), NULL, NULL, NULL, NULL); //����ַ
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
	// �˳�����
	PostQuitMessage(0);
	return 0;
}