// LOG.cpp : implementation file
//

#include "stdafx.h"
#include "UAC.h"
#include "LOG.h"
#include "UACDlg.h"

// CLOG dialog

IMPLEMENT_DYNAMIC(CLOG, CDialog)

CLOG::CLOG(CWnd* pParent /*=NULL*/)
	: CDialog(CLOG::IDD, pParent)
{

}

CLOG::~CLOG()
{
}

void CLOG::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_BTN_REFRESH, m_focus);
}


BEGIN_MESSAGE_MAP(CLOG, CDialog)
	ON_BN_CLICKED(IDC_BTN_REFRESH, &CLOG::OnBnClickedBtnRefresh)
END_MESSAGE_MAP()


// CLOG message handlers

void CLOG::OnBnClickedBtnRefresh()
{
	// TODO: Add your control notification handler code here
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);		
	GetDlgItem(IDC_EDT_LOG)->SetWindowText(pWnd->ShowTestLogData);
	SetWindowText(pWnd->ShowTestLogTitle);
	m_focus.SetFocus();
}

BOOL CLOG::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  Add extra initialization here
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);		
	GetDlgItem(IDC_EDT_LOG)->SetWindowText(pWnd->ShowTestLogData);
	SetWindowText(pWnd->ShowTestLogTitle);
	m_focus.SetFocus();
	return FALSE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}
