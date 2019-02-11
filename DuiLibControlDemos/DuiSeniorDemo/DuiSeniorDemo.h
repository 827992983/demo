#pragma once

#include "stdafx.h"

class CDuiMainWnd : public WindowImplBase
{
public:
	virtual LPCTSTR GetWindowClassName() const {
		return _T("CDuiMainWnd");
	}
	virtual CDuiString GetSkinFile() {
		return _T("DuiSeniorDemo.xml");
	}
	virtual CDuiString GetSkinFolder() { return _T(""); }
	void CDuiMainWnd::OnFinalMessage(HWND hWnd) {
		__super::OnFinalMessage(hWnd);
		delete this; //«Â¿Ì
	}

	virtual void InitWindow();

	virtual void Notify(TNotifyUI& msg);
	virtual LRESULT OnDestroy(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	virtual LRESULT HandleCustomMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);

private:
	CMenuWnd* m_pMenuFile;
	CMenuWnd* m_pMenuEdit;
	CMenuWnd* m_pMenuHelp;
};
