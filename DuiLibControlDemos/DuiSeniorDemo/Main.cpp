#include "DuiSeniorDemo.h"

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	CPaintManagerUI::SetInstance(hInstance);
	CDuiMainWnd* pFrame = new CDuiMainWnd();
	if (pFrame == NULL) return 0;
	pFrame->Create(NULL, _T("������"), UI_WNDSTYLE_FRAME, 0L, 0, 0, 800, 600);
	pFrame->CenterWindow();  //��ʾ���ڣ���ʹ���ڴ�����Ļ�м�
	CPaintManagerUI::MessageLoop();
	CPaintManagerUI::Term();// ������Դ
	return 0;
}