#include "DuiBaseDemo.h"
#include "DuiMessageBox.h"

DUI_BEGIN_MESSAGE_MAP(CDuiMainWnd, WindowImplBase)
	DUI_ON_MSGTYPE(DUI_MSGTYPE_CLICK, OnClick)
	DUI_ON_MSGTYPE(DUI_MSGTYPE_SELECTCHANGED, OnSelectChanged)
	DUI_ON_MSGTYPE(DUI_MSGTYPE_ITEMCLICK, OnItemClick)
DUI_END_MESSAGE_MAP()

void CDuiMainWnd::OnClick(TNotifyUI& msg)
{
	if (msg.sType == _T("click"))
	{
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

		if (msg.pSender->GetName() == _T("register_button")) 
		{
			//用户名
			CEditUI* pEditUserName = static_cast<CEditUI*>(m_pm.FindControl(_T("edit_username")));
			TCHAR* pstrUserName = (TCHAR*)pEditUserName->GetText().GetData();
			if (pstrUserName == NULL || lstrlen(pstrUserName) == 0) {
				CDuiMessageBox::ShowMessageBox(m_hWnd, _T("注册用户"), _T("请输入用户名！"));
				return;
			}

			//用户姓名
			CEditUI* pEditRealName = static_cast<CEditUI*>(m_pm.FindControl(_T("edit_realname")));
			TCHAR* pstrRealName = (TCHAR*)pEditRealName->GetText().GetData();
			if (pstrRealName == NULL || lstrlen(pstrRealName) == 0) {
				CDuiMessageBox::ShowMessageBox(m_hWnd, _T("注册用户"), _T("请输入用户姓名！"));
				return;
			}
			
			//密码
			CEditUI* pEditPassword = static_cast<CEditUI*>(m_pm.FindControl(_T("edit_password")));
			TCHAR* pstrPassword = (TCHAR*)pEditPassword->GetText().GetData();
			if (pstrPassword == NULL || lstrlen(pstrPassword) == 0) {
				CDuiMessageBox::ShowMessageBox(m_hWnd, _T("注册用户"), _T("请输入用户密码！"));
				return;
			}

			//性别
			COptionUI* pRadioGender = static_cast<COptionUI*>(m_pm.FindControl(_T("radio_boy")));
			TCHAR* pstrGender = NULL;
			if (pRadioGender->IsSelected())
			{
				pstrGender = (TCHAR*)pRadioGender->GetText().GetData();
			}
			pRadioGender = static_cast<COptionUI*>(m_pm.FindControl(_T("radio_girl")));
			if (pRadioGender->IsSelected())
			{
				pstrGender = (TCHAR*)pRadioGender->GetText().GetData();
			}
			if (pstrGender == NULL || lstrlen(pstrGender) == 0)
			{
				CDuiMessageBox::ShowMessageBox(m_hWnd, _T("注册用户"), _T("请选择性别！"));
				return;
			}

			//出生日期
			CDateTimeUI *pDateTimeBirthday = static_cast<CDateTimeUI*>(m_pm.FindControl(_T("datetime_birthday")));
			TCHAR* pstrBirthday = (TCHAR*)pDateTimeBirthday->GetText().GetData();
			if (pstrBirthday == NULL || lstrlen(pstrBirthday) == 0) {
				CDuiMessageBox::ShowMessageBox(m_hWnd, _T("注册用户"), _T("请选择出生日期！"));
				return;
			}

			//职位
			CComboBoxUI *pComBoxPosition = static_cast<CComboBoxUI*>(m_pm.FindControl(_T("positiont_type")));
			TCHAR *pstrPostion = (TCHAR *)pComBoxPosition->GetText().GetData();

			//爱好
			COptionUI* pCheckFootball = static_cast<COptionUI*>(m_pm.FindControl(_T("option_football")));
			TCHAR* pstrFootball = NULL;
			if (pCheckFootball->IsSelected())
			{
				pstrFootball = (TCHAR*)pCheckFootball->GetText().GetData();
			}
			COptionUI* pCheckBasketball = static_cast<COptionUI*>(m_pm.FindControl(_T("option_basketball")));
			TCHAR* pstrBasketball = NULL;
			if (pCheckBasketball->IsSelected())
			{
				pstrBasketball = (TCHAR*)pCheckBasketball->GetText().GetData();
			}
			COptionUI* pCheckTennisball = static_cast<COptionUI*>(m_pm.FindControl(_T("option_tennisball")));
			TCHAR* pstrTennisball = NULL;
			if (pCheckTennisball->IsSelected())
			{
				pstrTennisball = (TCHAR*)pCheckTennisball->GetText().GetData();
			}
			COptionUI* pCheckRead = static_cast<COptionUI*>(m_pm.FindControl(_T("option_read")));
			TCHAR* pstrRead = NULL;
			if (pCheckRead->IsSelected())
			{
				pstrRead = (TCHAR*)pCheckRead->GetText().GetData();
			}
			COptionUI* pCheckSing = static_cast<COptionUI*>(m_pm.FindControl(_T("option_sing")));
			TCHAR* pstrSing = NULL;
			if (pCheckSing->IsSelected())
			{
				pstrSing = (TCHAR*)pCheckSing->GetText().GetData();
			}
			COptionUI* pCheckDance = static_cast<COptionUI*>(m_pm.FindControl(_T("option_dance")));
			TCHAR* pstrDance = NULL;
			if (pCheckDance->IsSelected())
			{
				pstrDance = (TCHAR*)pCheckDance->GetText().GetData();
			}

			//自我介绍
			CRichEditUI *pRichEditDescription = static_cast<CRichEditUI*>(m_pm.FindControl(_T("richedit_description")));
			TCHAR* pstrDescription = (TCHAR*)pRichEditDescription->GetText().GetData();

			//写入结果
			TCHAR result[1024] = { 0 };
			lstrcat(result, _T("用户名："));
			lstrcat(result, pstrUserName);
			lstrcat(result, _T(","));

			lstrcat(result, _T("密码："));
			lstrcat(result, pstrPassword);
			lstrcat(result, _T(","));

			lstrcat(result, _T("姓名："));
			lstrcat(result, pstrRealName);
			lstrcat(result, _T(","));

			lstrcat(result, _T("性别："));
			lstrcat(result, pstrGender);
			lstrcat(result, _T(","));

			lstrcat(result, _T("出生日期："));
			lstrcat(result, pstrBirthday);
			lstrcat(result, _T(","));

			lstrcat(result, _T("爱好："));
			if (pstrBasketball != NULL && lstrlen(pstrBasketball)>0) 
			{
				lstrcat(result, pstrBasketball);
				lstrcat(result, _T("/"));
			}
			if (pstrFootball != NULL && lstrlen(pstrFootball)>0)
			{
				lstrcat(result, pstrFootball);
				lstrcat(result, _T("/"));
			}
			if (pstrTennisball != NULL && lstrlen(pstrTennisball)>0)
			{
				lstrcat(result, pstrTennisball);
				lstrcat(result, _T("/"));
			}
			if (pstrSing != NULL && lstrlen(pstrSing)>0)
			{
				lstrcat(result, pstrSing);
				lstrcat(result, _T("/"));
			}
			if (pstrRead != NULL && lstrlen(pstrRead)>0)
			{
				lstrcat(result, pstrRead);
				lstrcat(result, _T("/"));
			}
			if (pstrDance != NULL && lstrlen(pstrDance)>0)
			{
				lstrcat(result, pstrDance);
				lstrcat(result, _T("/"));
			}
			if (result[lstrlen(result) - 1] == _T('/'))
			{
				result[lstrlen(result) - 1] = _T('\0');
			}
			lstrcat(result, _T(","));

			lstrcat(result, _T("自我介绍："));
			lstrcat(result, pstrDescription);

			CLabelUI *pLabelResult = static_cast<CLabelUI*>(m_pm.FindControl(_T("label_result")));
			pLabelResult->SetText(result);
			CDuiMessageBox::ShowMessageBox(m_hWnd, _T("注册用户"), _T("用户注册成功！"));
			return;
		}
	}
}

void CDuiMainWnd::OnSelectChanged(TNotifyUI &msg)
{
	if (msg.pSender->GetName() == _T("down_list"))
	{
		static_cast<CTabLayoutUI*>(m_pm.FindControl(_T("tab_main")))->SelectItem(0);
	}
	else if (msg.pSender->GetName() == _T("down_his"))
	{
		static_cast<CTabLayoutUI*>(m_pm.FindControl(_T("tab_main")))->SelectItem(1);
	}
}

void CDuiMainWnd::OnItemClick(TNotifyUI &msg)
{

}

LRESULT CDuiMainWnd::OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& bHandled)
{
	bHandled = FALSE;
	// 退出程序
	PostQuitMessage(0);
	return 0;
}