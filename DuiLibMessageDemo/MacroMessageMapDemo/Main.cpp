#include "MacroMessageMapDemo.h"

/*
本例演示了通过消息映射宏：DUI_DECLARE_MESSAGE_MAP，DUI_BEGIN_MESSAGE_MAP，DUI_ON_MSGTYPE，DUI_END_MESSAGE_MAP实现DuiLib消息处理
类似于MFC的消息映射方式
由于WindowImplBase继承了CNotifyPump消息泵，所以，我们可以通过继承WindowImplBase来使用DuiLib消息映射宏来处理消息
此外：CNotifyPump还可以实现虚拟窗口，进行消息处理，在架构上进行模块化消息处理，并可增加代码的可读性
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
