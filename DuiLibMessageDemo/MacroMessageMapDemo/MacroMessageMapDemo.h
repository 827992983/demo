#pragma once

#include "stdafx.h"


class CDuiMainWnd : public WindowImplBase
{
public:
	CDuiMainWnd() {}
	~CDuiMainWnd() {}
	virtual LPCTSTR GetWindowClassName() const { return _T("CDuiFrameWnd"); }

	virtual CDuiString GetSkinFile() {
		return _T("MacroMessageMapDemo.xml");
	}
	virtual CDuiString GetSkinFolder() { return _T(""); }
	void CDuiMainWnd::OnFinalMessage(HWND hWnd) {
		__super::OnFinalMessage(hWnd);
		delete this;
	}
	void CDuiMainWnd::Notify(TNotifyUI &msg)
	{
		return WindowImplBase::Notify(msg);
	}

public: 
	// 系统消息
	LRESULT OnDestroy(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);

	//DuiLib消息映射宏
	DUI_DECLARE_MESSAGE_MAP()
	virtual void OnClick(TNotifyUI& msg);

protected:
	CPaintManagerUI m_PaintManager;
};