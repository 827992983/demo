#include "DuiActiveXDemo.h"

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	// 初始化COM组件
	HRESULT Hr = ::CoInitialize(NULL);
	if (FAILED(Hr)) return 0;
	// 初始化OLE的运行环境，OLE是在COM的基础上作的扩展，是ActiveX运行的基础
	HRESULT hRes = ::OleInitialize(NULL);

	CPaintManagerUI::SetInstance(hInstance);
	CDuiMainWnd* pFrame = new CDuiMainWnd();
	if (pFrame == NULL) return 0;
	pFrame->Create(NULL, _T("主窗口标题"), UI_WNDSTYLE_FRAME, 0L);
	pFrame->CenterWindow();
	CPaintManagerUI::MessageLoop();
	CPaintManagerUI::Term();// 清理资源
	
	// 清理OLE
	OleUninitialize();
	// 清理COM组件
	::CoUninitialize();
	return 0;
}
