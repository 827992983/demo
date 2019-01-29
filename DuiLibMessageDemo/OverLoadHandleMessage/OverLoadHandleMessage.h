#pragma once

#include "stdafx.h"


class CDuiMainWnd : public WindowImplBase
{
public:
	CDuiMainWnd() {}
	~CDuiMainWnd() {}
	virtual LPCTSTR GetWindowClassName() const { return _T("CDuiFrameWnd"); }

	virtual CDuiString GetSkinFile() {
		return _T("OverLoadHandleMessage.xml");
	}
	virtual CDuiString GetSkinFolder() { return _T(""); }
	void CDuiMainWnd::OnFinalMessage(HWND hWnd) {
		__super::OnFinalMessage(hWnd);
		delete this;
	}
	virtual void CDuiMainWnd::Notify(TNotifyUI &msg);

public: 
	// 系统消息
	virtual LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);

protected:
	CPaintManagerUI m_PaintManager;
};