#include "SimpleMainWindow.h"

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	CPaintManagerUI::SetInstance(hInstance);
	CDuiMainWnd* pFrame = new CDuiMainWnd();
	if (pFrame == NULL) return 0;
	pFrame->Create(NULL, _T("主窗口标题"), UI_WNDSTYLE_FRAME, 0L);
	pFrame->CenterWindow();
	CPaintManagerUI::MessageLoop();
	CPaintManagerUI::Term();// 清理资源
	return 0;
}
