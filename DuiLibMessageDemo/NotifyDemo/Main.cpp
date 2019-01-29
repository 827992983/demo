#include "NotifyDemo.h"

/*
本例演示了通过继承HandleMessage进行系统消息处理
由于WindowImplBase继承了CWindowWnd类，所以，我们可以通过继承WindowImplBase来重载HandleMessage处理系统消息

其实有不重载HandleMessage也可以，只需重载相关的消息处理函数也可以，
如：WM_CREATE，WM_CLOSE，WM_DESTROY，WM_SIZE，WM_CHAR的处理函数：OnCreate，OnClose，OnDestroy，OnSize，OnChar

本例演示的是重载了HandleMessage的情形
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
