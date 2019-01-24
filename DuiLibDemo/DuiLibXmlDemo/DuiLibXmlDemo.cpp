#include "DuiLibXmlDemo.h"

DUI_BEGIN_MESSAGE_MAP(CDuiFrameWnd, WindowImplBase)
	DUI_ON_MSGTYPE(DUI_MSGTYPE_CLICK, OnClick)
DUI_END_MESSAGE_MAP()

void CDuiFrameWnd::OnClick(TNotifyUI& msg)
{
	if (msg.sType == _T("click"))
	{
		if (msg.pSender->GetName() == _T("btnHello"))
		{
			MessageBox(NULL, _T("���ǰ�ťbtnHello��"), _T("DuiLib����"), MB_OK);
			return;
		}
	}

	MessageBox(NULL, _T("CDuiFrameWnd::OnClick"), _T("DuiLib����"), MB_OK);
}

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	CPaintManagerUI::SetInstance(hInstance);

	HRESULT Hr = ::CoInitialize(NULL);
	if (FAILED(Hr)) return 0;

	CDuiFrameWnd* pFrame = new CDuiFrameWnd();
	if (pFrame == NULL) return 0;
	pFrame->Create(NULL, _T("DuiLib ����"), UI_WNDSTYLE_FRAME, 0L);
	pFrame->CenterWindow();
	pFrame->ShowWindow();  //ʹ��ShowWindow���ͽ��룺CPaintManagerUI::MessageLoop()��Ϣѭ����Ҳ������ ::ShowWindow(*pFrame, SW_SHOW);
	CPaintManagerUI::MessageLoop();

	::CoUninitialize();
	return 0;
}
