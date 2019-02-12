#include "DuiSeniorDemo.h"
#include "DuiMessageBox.h"
#include <commdlg.h>

void CDuiMainWnd::Notify(TNotifyUI& msg)
{
	// slider
	if (msg.sType == _T("valuechanged"))
	{
		if (msg.pSender->GetName() == _T("slider"))
		{
			CProgressUI* pSlider = static_cast<CProgressUI*>(m_pm.FindControl(_T("slider")));
			CEditUI *pEditSlider = static_cast<CEditUI*>(m_pm.FindControl(_T("edit_slider_value")));
			TCHAR tSliderValue[4] = { 0 };
			_sntprintf(tSliderValue, 3, _T("%d"), pSlider->GetValue());
			pEditSlider->SetText(tSliderValue);
			return;
		}
	}
	if (msg.sType == _T("click"))
	{
		//menu
		if (msg.pSender->GetName() == _T("button_menu_file"))
		{
			if (m_pMenuFile != NULL) {
				delete m_pMenuFile;
				m_pMenuFile = NULL;
			}
			m_pMenuFile = new CMenuWnd();
			CDuiPoint point;
			RECT rect;
			GetWindowRect(m_hWnd, &rect);
			point.x = rect.left + 30;
			point.y = rect.top + 60;
			m_pMenuFile->Init(NULL, _T("file_menu.xml"), point, &m_pm);
			// 动态添加后重新设置菜单的大小
			m_pMenuFile->ResizeMenu();
			return;
		}
		if (msg.pSender->GetName() == _T("button_menu_edit"))
		{

			return;
		}
		if (msg.pSender->GetName() == _T("button_menu_help"))
		{

			return;
		}
		// process bar
		if (msg.pSender->GetName() == _T("button_next"))
		{
			CProgressUI* pProcess = static_cast<CProgressUI*>(m_pm.FindControl(_T("progress_standard")));
			if (pProcess->GetValue() < 100) {
				pProcess->SetValue(pProcess->GetValue() + 10);
			}
			else {
				pProcess->SetValue(10);
			}
			return;
		}
		//system button
		if (msg.pSender->GetName() == _T("closebtn"))
		{
			int ret = CDuiMessageBox::MessageBox(m_hWnd, _T("演示程序"), _T("确定退出演示程序？"));
			if (ret == MSGID_OK) {
				DestroyWindow(m_hWnd);
			}
			return;
		}
		if (msg.pSender->GetName() == _T("minbtn"))
		{
			SendMessage(WM_SYSCOMMAND, SC_MINIMIZE, 0);
			return;
		}
		if (msg.pSender->GetName() == _T("maxbtn"))
		{
			SendMessage(WM_SYSCOMMAND, SC_MAXIMIZE, 0);
			return;
		}
		if (msg.pSender->GetName() == _T("restorebtn"))
		{
			SendMessage(WM_SYSCOMMAND, SC_RESTORE, 0);
			return;
		}
	}
	__super::Notify(msg);
}

LRESULT CDuiMainWnd::HandleCustomMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	if (uMsg == WM_MENUCLICK)
	{
		MenuCmd* pMenuCmd = (MenuCmd*)wParam;
		if (pMenuCmd != NULL)
		{
			BOOL bChecked = pMenuCmd->bChecked;
			CDuiString sMenuName = pMenuCmd->szName;
			CDuiString sUserData = pMenuCmd->szUserData;
			CDuiString sText = pMenuCmd->szText;
			m_pm.DeletePtr(pMenuCmd);

			if (sMenuName.CompareNoCase(_T("open_file")) == 0)
			{
				TCHAR szFilePath[1024] = { 0 };   // 所选择的文件最终的路径
				OPENFILENAME ofn = { 0 };
				ofn.lStructSize = sizeof(ofn);
				ofn.hwndOwner = m_hWnd;
				ofn.lpstrFilter = _T("txt文件(*.txt)");//要选择的文件后缀   
				ofn.lpstrInitialDir = _T(".");//默认的文件路径   
				ofn.lpstrFile = szFilePath;//存放文件的缓冲区   
				ofn.nMaxFile = sizeof(szFilePath) / sizeof(*szFilePath);
				ofn.nFilterIndex = 0;
				ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER; //标志如果是多选要加上OFN_ALLOWMULTISELECT 
				if (!GetOpenFileName(&ofn))
				{
					return 0;
				}
				CDuiMessageBox::ShowMessageBox(m_hWnd, _T("选择文件"), szFilePath);
			}
			else if (sMenuName == _T("exit")) {
				Close(0);
			}
			else
			{
				CDuiMessageBox::ShowMessageBox(m_hWnd, _T("菜单项"), sText);
			}
		}
		bHandled = TRUE;
		return 0;
	}

	bHandled = FALSE;
	return 0;
}

LRESULT CDuiMainWnd::OnDestroy(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	bHandled = FALSE;
	// 退出程序
	PostQuitMessage(0);
	return 0;
}

void CDuiMainWnd::InitWindow() 
{
	// List控件添加元素
	CListUI* pList = static_cast<CListUI*>(m_pm.FindControl(_T("listview")));
	for (int i = 0; i < 20; i++)
	{
		CListTextElementUI* pItem = new CListTextElementUI();
		pItem->SetFixedHeight(30);
		pList->Add(pItem);
		pItem->SetText(0, _T("张三"));
		pItem->SetText(1, _T("1000"));
		pItem->SetText(2, _T("100"));
		pItem->SetText(3, _T("无"));
	}
}
