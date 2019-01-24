// Win32Demo.cpp : 定义应用程序的入口点。
//

#include "stdafx.h"
#include "Win32Demo.h"

//字符数组长度
#define MAX_LOADSTRING 100

//全局变量
HINSTANCE hInst;                                                        // 当前实例
TCHAR g_szTitle[MAX_LOADSTRING] = TEXT("Win32程序测试");				// 窗口标题
TCHAR g_szWindowClass[MAX_LOADSTRING] = TEXT("Win32Demo测试");			// 窗口类的名称
HWND g_hWnd;                                                            // 窗口句柄
bool g_bWhite = false;                                                  // 是否为白色背景


																		// 注册窗口类（初始化：HINSTANCE对象）
ATOM AppRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc; //消息处理函数
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = NULL;
	wcex.lpszClassName = g_szWindowClass;
	wcex.hIconSm = NULL;

	return RegisterClassEx(&wcex);
}


// 保存实例化句柄并创建主窗口
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	hInst = hInstance; // 保存handle到全局变量
	g_hWnd = CreateWindow(g_szWindowClass, g_szTitle, WS_OVERLAPPEDWINDOW, 0, 0, 400, 300, NULL, NULL, hInstance, NULL);
	// 创建按钮
	HWND hBtWhite = CreateWindowEx(0, L"Button", L"白色背景", WS_CHILD | WS_VISIBLE | BS_TEXT, 180, 200, 80, 30, g_hWnd, (HMENU)ID_BUTTON_DRAW, hInst, NULL);
	HWND hBtGray = CreateWindowEx(0, L"Button", L"灰色背景", WS_CHILD | WS_VISIBLE | BS_CENTER, 280, 200, 80, 30, g_hWnd, (HMENU)ID_BUTTON_SWEEP, hInst, NULL);

	if (!g_hWnd)
	{
		return FALSE;
	}
	ShowWindow(g_hWnd, nCmdShow);
	UpdateWindow(g_hWnd);

	return TRUE;
}

//事件处理
//按下hBtWhite时的事件
void OnButtonWhite()
{
	g_bWhite = true;
	InvalidateRect(g_hWnd, NULL, FALSE);    //刷新窗口
}

//按下hBtGray时的事件
void OnButtonGray()
{
	g_bWhite = false;
	InvalidateRect(g_hWnd, NULL, FALSE);    //刷新窗口
}

//绘制事件(每次刷新时重新绘制图像)
void OnDraw(HDC hdc)
{
	POINT oldPoint;
	SetViewportOrgEx(hdc, 0, 0, &oldPoint);
	RECT rcView;
	GetWindowRect(g_hWnd, &rcView); // 获得句柄的画布大小
	HBRUSH hbrWhite = (HBRUSH)GetStockObject(WHITE_BRUSH);
	HBRUSH hbrGray = (HBRUSH)GetStockObject(GRAY_BRUSH);
	if (g_bWhite)
	{
		FillRect(hdc, &rcView, hbrWhite);
	}
	else
	{
		FillRect(hdc, &rcView, hbrGray);
	}
	SetViewportOrgEx(hdc, oldPoint.x, oldPoint.y, NULL);
}

// (窗口)消息处理
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;

	switch (message)
	{
	case WM_COMMAND:
		wmId = LOWORD(wParam);

		switch (wmId)
		{
		case ID_BUTTON_DRAW:
			OnButtonWhite();
			break;
		case ID_BUTTON_SWEEP:
			OnButtonGray();
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
	case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		OnDraw(hdc);
		EndPaint(hWnd, &ps);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

//WinMain入口函数
int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	// 注册窗口类
	if (!AppRegisterClass(hInstance))
	{
		return (FALSE);
	}
	// 初始化应用程序窗口
	if (!InitInstance(hInstance, nCmdShow))
	{
		return FALSE;
	}

	// 进入消息循环
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return (int)msg.wParam;
}
