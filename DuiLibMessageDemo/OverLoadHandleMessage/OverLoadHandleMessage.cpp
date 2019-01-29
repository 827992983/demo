#include "OverLoadHandleMessage.h"


void CDuiMainWnd::Notify(TNotifyUI& msg)
{
	if (msg.sType == _T("click"))
	{
		if (msg.pSender->GetName() == _T("closebtn"))
		{
			::DestroyWindow(m_hWnd);
			return;
		}
	}
}

/*
ֱ��������WindowImplBase���HandleMessage��OnDestroy����
*/
LRESULT CDuiMainWnd::HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam)//�Ի������
{
	LRESULT lRes = 0;
	if (uMsg == WM_CREATE)
	{
		__super::HandleMessage(uMsg, wParam, lParam);
		//TODO������WM_CREATE��Ϣ��ϣ�����������������

		return lRes;
	}
	// TODO������WM_DESTROY���ڴ������ٺ��˳�����
	else if (uMsg == WM_DESTROY)
	{
		::PostQuitMessage(0L);
		return 0;
	}

	return __super::HandleMessage(uMsg, wParam, lParam);
}