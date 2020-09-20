#include <windows.h>// Windows ͷ�ļ�
#include <tchar.h>

#define ID_BUTTON_1      1000

LRESULT WINAPI MsgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	int wmId;

	switch (msg)
	{
	case WM_COMMAND:
		wmId = LOWORD(wParam);
		//wmEvent = HIWORD(wParam);

		switch (wmId)
		{
		case ID_BUTTON_1:
			MessageBox(hWnd, _T("I am system MessageBox"), _T("TEST"), MB_OK | MB_ICONINFORMATION);
			break;
		default:
			return DefWindowProc(hWnd, msg, wParam, lParam);
		}
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
		break;
	case WM_KEYUP:
		if (wParam == VK_ESCAPE)
			PostQuitMessage(0);
		break;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE prevhInst, LPSTR cmdLine, int
	show)
{
	//Register the window class
	WNDCLASSEX wc = { sizeof(WNDCLASSEX),CS_CLASSDC,MsgProc,0L,0L,
		GetModuleHandle(NULL),NULL,NULL,NULL,NULL,
		_T("AppClass"),NULL };
	RegisterClassEx(&wc);

	//create the application's window
	HWND hWnd = CreateWindow(_T("AppClass"), _T("EasyHook Test"), WS_OVERLAPPEDWINDOW,
		200, 200, 640, 480, NULL, NULL,
		hInst, NULL);
	HWND hBtTest = CreateWindowEx(0, L"Button", L"Click Me", WS_CHILD | WS_VISIBLE | BS_TEXT, 100, 100, 100, 30, hWnd, (HMENU)ID_BUTTON_1, hInst, NULL);
	ShowWindow(hWnd, SW_SHOWDEFAULT);
	UpdateWindow(hWnd);

	//enter the message loop
	MSG msg;
	ZeroMemory(&msg, sizeof(msg));//����0�����һ���ڴ�����

	while (msg.message != WM_QUIT)
	{
		if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))//����Ϣ�����л�ȡ��һ����Ϣ
		{
			TranslateMessage(&msg);//�������Ϣ����һЩת��
			DispatchMessage(&msg);//��ת�������Ϣ���͸���Ϣ���̺���
		}
		else
		{
			//��������Ļ����ͼ��Ĵ��벿��
		}
	}
	UnregisterClass(_T("AppClass"), wc.hInstance);//ȡ���Դ������ע��
	return 0;
}