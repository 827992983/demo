#include "DuiButtons.h"

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	CPaintManagerUI::SetInstance(hInstance);

	HRESULT Hr = ::CoInitialize(NULL);
	if (FAILED(Hr)) return 0;

	CDuiMainWnd* pFrame = new CDuiMainWnd();
	if (pFrame == NULL) return 0;
	pFrame->Create(NULL, _T("������"), UI_WNDSTYLE_FRAME, 0L);
	pFrame->CenterWindow();
	pFrame->ShowWindow();  //ʹ��ShowWindow���ͽ��룺CPaintManagerUI::MessageLoop()��Ϣѭ����Ҳ������ ::ShowWindow(*pFrame, SW_SHOW);
	CPaintManagerUI::MessageLoop();

	::CoUninitialize();
	return 0;
}
