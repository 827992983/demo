#pragma once

//////////////////////////////////////////////////////////////////////////
///
#define MSGID_OK		1
#define MSGID_CANCEL	0
class CDuiMessageBox : public WindowImplBase
{
public:
	static int MessageBox(HWND hParent, LPCTSTR lpstrTitle, LPCTSTR lpstrMsg)
	{
		CDuiMessageBox* pWnd = new CDuiMessageBox();
		pWnd->Create(hParent, _T("DuiMessageBox"), WS_POPUP | WS_CLIPCHILDREN, WS_EX_TOOLWINDOW);
		pWnd->CenterWindow();
		pWnd->SetTitle(lpstrTitle);
		pWnd->SetMsg(lpstrMsg);
		return pWnd->ShowModal();
	}

	static void ShowMessageBox(HWND hParent, LPCTSTR lpstrTitle, LPCTSTR lpstrMsg)
	{
		CDuiMessageBox* pWnd = new CDuiMessageBox();
		pWnd->Create(hParent, _T("DuiMessageBox"), WS_POPUP | WS_CLIPCHILDREN, WS_EX_TOOLWINDOW);
		pWnd->CenterWindow();
		pWnd->SetTitle(lpstrTitle);
		pWnd->SetMsg(lpstrMsg);
		CButtonUI* cancelBtn = static_cast<CButtonUI*>(pWnd->m_pm.FindControl(_T("msg_cancel_btn")));
		cancelBtn->SetVisible(false);
		pWnd->ShowModal();
	}

public:
	CDuiMessageBox(void);
	~CDuiMessageBox(void);

	void SetMsg(LPCTSTR lpstrMsg);
	void SetTitle(LPCTSTR lpstrTitle);

public:
	virtual void OnFinalMessage( HWND );
	virtual CDuiString GetSkinFile();
	virtual LPCTSTR GetWindowClassName( void ) const;
	virtual void Notify( TNotifyUI &msg );
	virtual void InitWindow();

	DUI_DECLARE_MESSAGE_MAP()
	virtual void OnClick(TNotifyUI& msg);

	virtual LRESULT OnSysCommand( UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled );
	LRESULT HandleCustomMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);

private:
	CButtonUI* m_pCloseBtn;
};
