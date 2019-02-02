#include "DuiButtons.h"

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{

	// 显示当前进程的内存泄漏
	_CrtDumpMemoryLeaks();
	// 初始化COM组件
	HRESULT Hr = ::CoInitialize(NULL);
	if (FAILED(Hr)) return 0;
	// 初始化OLE的运行环境，OLE是在COM的基础上作的扩展，是ActiveX运行的基础
	HRESULT hRes = ::OleInitialize(NULL);

	CPaintManagerUI::SetInstance(hInstance);
	CDuiMainWnd* pFrame = new CDuiMainWnd();
	if (pFrame == NULL) return 0;
	pFrame->Create(NULL, _T("主窗口"), UI_WNDSTYLE_FRAME, 0L);
	pFrame->CenterWindow();
	pFrame->ShowWindow();  //使用ShowWindow，就进入：CPaintManagerUI::MessageLoop()消息循环，也可以用 ::ShowWindow(*pFrame, SW_SHOW);
	CPaintManagerUI::MessageLoop();
	CPaintManagerUI::Term();// 清理资源

	// 清理OLE
	OleUninitialize();
	// 清理COM组件
	::CoUninitialize();
	return 0;
}
