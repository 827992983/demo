#include "DuiButtons.h"

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{

	// ��ʾ��ǰ���̵��ڴ�й©
	_CrtDumpMemoryLeaks();
	// ��ʼ��COM���
	HRESULT Hr = ::CoInitialize(NULL);
	if (FAILED(Hr)) return 0;
	// ��ʼ��OLE�����л�����OLE����COM�Ļ�����������չ����ActiveX���еĻ���
	HRESULT hRes = ::OleInitialize(NULL);

	CPaintManagerUI::SetInstance(hInstance);
	CDuiMainWnd* pFrame = new CDuiMainWnd();
	if (pFrame == NULL) return 0;
	pFrame->Create(NULL, _T("������"), UI_WNDSTYLE_FRAME, 0L);
	pFrame->CenterWindow();
	pFrame->ShowWindow();  //ʹ��ShowWindow���ͽ��룺CPaintManagerUI::MessageLoop()��Ϣѭ����Ҳ������ ::ShowWindow(*pFrame, SW_SHOW);
	CPaintManagerUI::MessageLoop();
	CPaintManagerUI::Term();// ������Դ

	// ����OLE
	OleUninitialize();
	// ����COM���
	::CoUninitialize();
	return 0;
}
