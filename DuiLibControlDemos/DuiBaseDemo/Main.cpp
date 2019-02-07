#include "DuiBaseDemo.h"

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	CPaintManagerUI::SetInstance(hInstance);
	CDuiMainWnd* pFrame = new CDuiMainWnd();
	if (pFrame == NULL) return 0;
	pFrame->Create(NULL, _T("主窗口"), UI_WNDSTYLE_FRAME, 0L);
	pFrame->CenterWindow();  //显示窗口，并使窗口处于屏幕中间
	CPaintManagerUI::MessageLoop();
	CPaintManagerUI::Term();// 清理资源
	return 0;
}
