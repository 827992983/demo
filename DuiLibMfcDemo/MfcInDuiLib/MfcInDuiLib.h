#pragma once
#include "stdafx.h"


class CWndUI : public CControlUI
{
public:
	CWndUI() : m_hWnd(NULL) {}
	virtual void SetInternVisible(bool bVisible = true)
	{
		__super::SetInternVisible(bVisible);
		::ShowWindow(m_hWnd, bVisible);
	}
	virtual void SetPos(RECT rc)
	{
		__super::SetPos(rc);
		::SetWindowPos(m_hWnd, NULL, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, SWP_NOZORDER | SWP_NOACTIVATE);
	}
	BOOL Attach(HWND hWndNew)
	{
		if (!::IsWindow(hWndNew))
		{
			return FALSE;
		}
		m_hWnd = hWndNew;
		return TRUE;
	}
	HWND Detach()
	{
		HWND hWnd = m_hWnd;
		m_hWnd = NULL;
		return hWnd;
	}

protected:
	HWND m_hWnd;
};

class CDuiFrameWnd : public WindowImplBase
{
public:
	virtual LPCTSTR GetWindowClassName() const {
		return _T("DUIMainFrame");
	}
	virtual CDuiString GetSkinFile() {
		return _T("MfcInDuiLib.xml");
	}
	virtual CDuiString GetSkinFolder() { return _T(""); }

	virtual CControlUI* CreateControl(LPCTSTR pstrClassName)
	{
		if (_tcsicmp(pstrClassName, _T("Wnd")) == 0)
		{
			// 这段用的是win32 的按钮
			//CWndUI *pUI = new CWndUI();
			//HWND hWnd = CreateWindow(_T("BUTTON"), _T("win32"), WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 265, 90, 120, 28, m_PaintManager.GetPaintWindow(), NULL, NULL, NULL);
			//pUI->Attach(hWnd);

			//这段用MFC 的按钮
			CWndUI *pUI = new CWndUI();
			CButton *pBtn = new CButton; // 记得释放内存
			pBtn->Create(_T("MFC"), WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, CRect(100, 100, 180, 150), CWnd::FromHandle(m_PaintManager.GetPaintWindow()), 0);
			pUI->Attach(*pBtn);

			// 这段用win32时间控件
			//CWndUI *pUI = new CWndUI();
			//pUI->Attach(CreateWindow(_T("SysDateTimePick32"), _T(""), WS_VISIBLE | WS_CHILD | DTS_TIMEFORMAT, 265, 90, 120, 28, m_PaintManager.GetPaintWindow(), NULL, NULL, NULL));

			return pUI;
		}
		return NULL;
	}
};
