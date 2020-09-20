#include <windows.h>// Windows 头文件
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
	ZeroMemory(&msg, sizeof(msg));//宏用0来填充一块内存区域

	while (msg.message != WM_QUIT)
	{
		if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))//从消息队列中获取下一条消息
		{
			TranslateMessage(&msg);//对相关消息进行一些转换
			DispatchMessage(&msg);//将转换后的消息发送给消息过程函数
		}
		else
		{
			//处理向屏幕绘制图像的代码部分
		}
	}
	UnregisterClass(_T("AppClass"), wc.hInstance);//取消对窗口类的注册
	return 0;
}