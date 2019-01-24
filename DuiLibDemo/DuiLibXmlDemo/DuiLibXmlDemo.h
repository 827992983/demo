#pragma once

#include "stdafx.h"


class CDuiFrameWnd : public WindowImplBase
{
public:
	CDuiFrameWnd() {}
	~CDuiFrameWnd() {}
	virtual LPCTSTR GetWindowClassName() const { return _T("CDuiFrameWnd"); }

	virtual CDuiString GetSkinFile() {
		return _T("DuiLibXmlDemo.xml");
	}
	virtual CDuiString GetSkinFolder() { return _T(""); }
	void CDuiFrameWnd::OnFinalMessage(HWND hWnd) {
		__super::OnFinalMessage(hWnd);
		delete this;
	}
	void CDuiFrameWnd::Notify(TNotifyUI &msg)
	{
		return WindowImplBase::Notify(msg);
	}


	DUI_DECLARE_MESSAGE_MAP()
	virtual void OnClick(TNotifyUI& msg);

protected:
	CPaintManagerUI m_PaintManager;
};