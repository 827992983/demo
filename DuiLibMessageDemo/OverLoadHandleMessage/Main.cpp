#include "OverLoadHandleMessage.h"

/*
本例演示了通过继承INotifyUI接口实现DuiLib消息处理
由于WindowImplBase继承了INotifyUI接口，所以，我们可以通过继承WindowImplBase来重载Notify函数实现DuiLib消息处理
*/
int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	CPaintManagerUI::SetInstance(hInstance);

	HRESULT Hr = ::CoInitialize(NULL);
	if (FAILED(Hr)) return 0;

	CDuiMainWnd* pFrame = new CDuiMainWnd();
	if (pFrame == NULL) return 0;
	pFrame->Create(NULL, _T("主窗口标题"), UI_WNDSTYLE_FRAME, 0L);
	pFrame->CenterWindow();
	pFrame->ShowWindow();  //使用ShowWindow，就进入：CPaintManagerUI::MessageLoop()消息循环，也可以用 ::ShowWindow(*pFrame, SW_SHOW);
	CPaintManagerUI::MessageLoop();

	::CoUninitialize();
	return 0;
}
