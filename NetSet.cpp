// NetSet.cpp : implementation file
//

#include "stdafx.h"
#include "UAC.h"
#include "NetSet.h"
#include "UACDlg.h"

// CNetSet dialog

IMPLEMENT_DYNAMIC(CNetSet, CDialog)

CNetSet::CNetSet(CWnd* pParent /*=NULL*/)
	: CDialog(CNetSet::IDD, pParent)
{

}

CNetSet::~CNetSet()
{
}

void CNetSet::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_BTN_OK, m_kAlterBtn);
}


BEGIN_MESSAGE_MAP(CNetSet, CDialog)
	ON_BN_CLICKED(IDC_BTN_OK, &CNetSet::OnBnClickedBtnOk)
END_MESSAGE_MAP()


// CNetSet message handlers

void CNetSet::OnBnClickedBtnOk()
{
	// TODO: Add your control notification handler code here
	HWND   hnd=::FindWindow(NULL, _T("UAC"));
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	static BOOL bAlter=TRUE;	
	if(bAlter)
	{
		m_kAlterBtn.SetWindowText(_T("È·¶¨"));
		//±¾µØÍøÂçÅäÖÃ 
		GetDlgItem(IDC_EDT_CLIENT_PORT)->EnableWindow(TRUE);
		GetDlgItem(IDC_EDT_TCP_PORT)->EnableWindow(TRUE);
		GetDlgItem(IDC_EDT_CLIENT_ADD)->EnableWindow(TRUE);
		GetDlgItem(IDC_EDT_CLIENT_NAME)->EnableWindow(TRUE);	
		//Ô¶³ÌÍøÂçÅäÖÃ
		GetDlgItem(IDC_IP_SERVER)->EnableWindow(TRUE);
		GetDlgItem(IDC_EDT_SERVER_PORT)->EnableWindow(TRUE);
		GetDlgItem(IDC_EDT_SERVER_ADD)->EnableWindow(TRUE);
		GetDlgItem(IDC_EDT_SERVER_NAME)->EnableWindow(TRUE);
		bAlter=FALSE;
		pWnd->bNetSet=FALSE;
	}
	else
	{		
		//¸üÐÂÍøÂçÅäÖÃÊôÐÔ
		CString LocalHostName;
		pWnd->GetLocalHostName(LocalHostName);
		pWnd->GetLocalIp(LocalHostName,pWnd->m_InfoClient.IP);
		GetDlgItem(IDC_IP_CLIENT)->SetWindowText(pWnd->m_InfoClient.IP);
		GetDlgItem(IDC_EDT_CLIENT_PORT)->GetWindowText(pWnd->m_InfoClient.Port);
		GetDlgItem(IDC_EDT_TCP_PORT)->GetWindowText(pWnd->TCP_Port);
		GetDlgItem(IDC_EDT_CLIENT_ADD)->GetWindowText(pWnd->m_InfoClient.UserAddress);
		GetDlgItem(IDC_EDT_CLIENT_NAME)->GetWindowText(pWnd->m_InfoClient.UserName);
		pWnd->GetDlgItem(IDC_STR_LOCAL_IP)->SetWindowText(pWnd->m_InfoClient.IP);
		pWnd->GetDlgItem(IDC_STR_LOCAL_PORT)->SetWindowText(pWnd->m_InfoClient.Port);
		pWnd->GetDlgItem(IDC_STR_LOCAL_ADD)->SetWindowText(pWnd->m_InfoClient.UserAddress);
		pWnd->GetDlgItem(IDC_STR_LOCAL_NAME)->SetWindowText(pWnd->m_InfoClient.UserName);

		GetDlgItem(IDC_IP_SERVER)->GetWindowText(pWnd->m_InfoServer.IP);
		GetDlgItem(IDC_EDT_SERVER_PORT)->GetWindowText(pWnd->m_InfoServer.Port);
		GetDlgItem(IDC_EDT_SERVER_ADD)->GetWindowText(pWnd->m_InfoServer.UserAddress);
		GetDlgItem(IDC_EDT_SERVER_NAME)->GetWindowText(pWnd->m_InfoServer.UserName);
		pWnd->GetDlgItem(IDC_STR_REMOTE_IP)->SetWindowText(pWnd->m_InfoServer.IP);
		pWnd->GetDlgItem(IDC_STR_REMOTE_PORT)->SetWindowText(pWnd->m_InfoServer.Port);
		pWnd->GetDlgItem(IDC_STR_REMOTE_ADD)->SetWindowText(pWnd->m_InfoServer.UserAddress);
		pWnd->GetDlgItem(IDC_STR_REMOTE_NAME)->SetWindowText(pWnd->m_InfoServer.UserName);
		if (pWnd->m_InfoClient.IP=="" || pWnd->m_InfoClient.Port=="" ||pWnd->m_InfoClient.UserAddress=="" ||pWnd->m_InfoClient.UserName=="")
		{
			AfxMessageBox("Çë¼ì²éÍøÂçÅäÖÃÊÇ·ñÎª¿Õ!");
			return;
		}
		if (pWnd->m_InfoServer.IP=="" || pWnd->m_InfoServer.Port=="" ||pWnd->m_InfoServer.UserAddress=="" ||pWnd->m_InfoServer.UserName=="")
		{
			AfxMessageBox("Çë¼ì²éÍøÂçÅäÖÃÊÇ·ñÎª¿Õ!");
			return;
		}	
		//³õÊ¼»¯ÍøÂçÅäÖÃÎÄ¼þ
		FILE *NetFile=NULL;		
		NetFile=fopen("UACNetLog.txt","w");	
		fprintf(NetFile,pWnd->m_InfoClient.Port);	
		fprintf(NetFile,"\n");
		fprintf(NetFile,pWnd->TCP_Port);	
		fprintf(NetFile,"\n");
		fprintf(NetFile,pWnd->m_InfoClient.UserName);
		fprintf(NetFile,"\n");
		fprintf(NetFile,pWnd->m_InfoClient.UserAddress);
		fprintf(NetFile,"\n");
		fprintf(NetFile,pWnd->m_InfoServer.IP);
		fprintf(NetFile,"\n");
		fprintf(NetFile,pWnd->m_InfoServer.Port);
		fprintf(NetFile,"\n");
		fprintf(NetFile,pWnd->m_InfoServer.UserName);
		fprintf(NetFile,"\n");
		fprintf(NetFile,pWnd->m_InfoServer.UserAddress);		
		if (NetFile)
		{
			fclose(NetFile);
		}
		pWnd->bNetSet=TRUE;
		m_kAlterBtn.SetWindowText(_T("ÐÞ¸Ä"));
		//±¾µØÍøÂçÅäÖÃ 
		GetDlgItem(IDC_EDT_CLIENT_PORT)->EnableWindow(FALSE);
		GetDlgItem(IDC_EDT_TCP_PORT)->EnableWindow(FALSE);
		GetDlgItem(IDC_EDT_CLIENT_ADD)->EnableWindow(FALSE);
		GetDlgItem(IDC_EDT_CLIENT_NAME)->EnableWindow(FALSE);	
		//Ô¶³ÌÍøÂçÅäÖÃ
		GetDlgItem(IDC_IP_SERVER)->EnableWindow(FALSE);
		GetDlgItem(IDC_EDT_SERVER_PORT)->EnableWindow(FALSE);
		GetDlgItem(IDC_EDT_SERVER_ADD)->EnableWindow(FALSE);
		GetDlgItem(IDC_EDT_SERVER_NAME)->EnableWindow(FALSE);
		bAlter=TRUE;
	}
}
