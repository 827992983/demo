#include "OverLoadHandleMessage.h"

/*
������ʾ��ͨ���̳�INotifyUI�ӿ�ʵ��DuiLib��Ϣ����
����WindowImplBase�̳���INotifyUI�ӿڣ����ԣ����ǿ���ͨ���̳�WindowImplBase������Notify����ʵ��DuiLib��Ϣ����
*/
int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	CPaintManagerUI::SetInstance(hInstance);

	HRESULT Hr = ::CoInitialize(NULL);
	if (FAILED(Hr)) return 0;

	CDuiMainWnd* pFrame = new CDuiMainWnd();
	if (pFrame == NULL) return 0;
	pFrame->Create(NULL, _T("�����ڱ���"), UI_WNDSTYLE_FRAME, 0L);
	pFrame->CenterWindow();
	pFrame->ShowWindow();  //ʹ��ShowWindow���ͽ��룺CPaintManagerUI::MessageLoop()��Ϣѭ����Ҳ������ ::ShowWindow(*pFrame, SW_SHOW);
	CPaintManagerUI::MessageLoop();

	::CoUninitialize();
	return 0;
}
