#include "DuiActiveXDemo.h"

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	// ��ʼ��COM���
	HRESULT Hr = ::CoInitialize(NULL);
	if (FAILED(Hr)) return 0;
	// ��ʼ��OLE�����л�����OLE����COM�Ļ�����������չ����ActiveX���еĻ���
	HRESULT hRes = ::OleInitialize(NULL);

	CPaintManagerUI::SetInstance(hInstance);
	CDuiMainWnd* pFrame = new CDuiMainWnd();
	if (pFrame == NULL) return 0;
	pFrame->Create(NULL, _T("�����ڱ���"), UI_WNDSTYLE_FRAME, 0L);
	pFrame->CenterWindow();
	CPaintManagerUI::MessageLoop();
	CPaintManagerUI::Term();// ������Դ
	
	// ����OLE
	OleUninitialize();
	// ����COM���
	::CoUninitialize();
	return 0;
}
