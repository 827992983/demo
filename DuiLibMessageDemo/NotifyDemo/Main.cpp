#include "NotifyDemo.h"

/*
������ʾ��ͨ���̳�HandleMessage����ϵͳ��Ϣ����
����WindowImplBase�̳���CWindowWnd�࣬���ԣ����ǿ���ͨ���̳�WindowImplBase������HandleMessage����ϵͳ��Ϣ

��ʵ�в�����HandleMessageҲ���ԣ�ֻ��������ص���Ϣ������Ҳ���ԣ�
�磺WM_CREATE��WM_CLOSE��WM_DESTROY��WM_SIZE��WM_CHAR�Ĵ�������OnCreate��OnClose��OnDestroy��OnSize��OnChar

������ʾ����������HandleMessage������
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
