#pragma once

#include "stdafx.h"


class CDuiMainWnd : public WindowImplBase
{
public:
	CDuiMainWnd() {}
	~CDuiMainWnd() {}
	virtual LPCTSTR GetWindowClassName() const { return _T("CDuiFrameWnd"); }

	virtual CDuiString GetSkinFile() {
		return _T("NotifyDemo.xml");
	}
	virtual CDuiString GetSkinFolder() { return _T(""); }
	void CDuiMainWnd::OnFinalMessage(HWND hWnd) {
		__super::OnFinalMessage(hWnd);
		delete this;
	}

public:
	virtual void Notify(TNotifyUI& msg);// ʵ��INotifyUI������CPaintManagerUI::AddNotifier�����������Notifier����(WindowImplBase�Ѿ���ӣ�
	LRESULT CDuiMainWnd::OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& bHandled);

protected:
	CPaintManagerUI m_PaintManager;
};