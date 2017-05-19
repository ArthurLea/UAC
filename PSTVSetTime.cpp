// PSTVSetTime.cpp : 实现文件
//

#include "stdafx.h"
#include "UAC.h"
#include "PSTVSetTime.h"
#include "afxdialogex.h"
#include "UACDlg.h"
extern queue<UA_Msg> uac_sendqueue;
extern CRITICAL_SECTION g_uac;

// CPSTVSetTime 对话框

IMPLEMENT_DYNAMIC(CPSTVSetTime, CDialogEx)

CPSTVSetTime::CPSTVSetTime(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DLG_PSTVTIME, pParent)
{

}

CPSTVSetTime::~CPSTVSetTime()
{
}

void CPSTVSetTime::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_URL, m_Edit_url);
}


BEGIN_MESSAGE_MAP(CPSTVSetTime, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON_PSTVTIME, &CPSTVSetTime::OnBnClickedButtonPstvtime)
END_MESSAGE_MAP()

BOOL CPSTVSetTime::OnInitDialog()
{
	CDialog::OnInitDialog();

	GetDlgItem(IDC_EDIT_PRIVILEGE)->SetWindowTextA("0100100001");
	GetDlgItem(IDC_EDIT_URL)->SetWindowTextA("http://192.168.9.115/1.png");
	return TRUE;
}

// CPSTVSetTime 消息处理程序

//IDC_EDIT_PRIVILEGE

void CPSTVSetTime::OnBnClickedButtonPstvtime()
{
	HWND   hnd = ::FindWindow(NULL, _T("UAC"));
	CUACDlg*  pWnd = (CUACDlg*)CWnd::FromHandle(hnd);

	CString privilege;
	GetDlgItem(IDC_EDIT_PRIVILEGE)->GetWindowTextA(privilege);
	//get information and create XML message	
	string XmlTimeSet;
	XmlTimeSet = "<?xml version=\"1.0\"?>\r\n";
	XmlTimeSet += "<Action>\r\n";
	XmlTimeSet += "<Notify>\r\n";
	XmlTimeSet += "<Variable>TimeGet</Variable>\r\n";
	XmlTimeSet += "<Privilege>"+ privilege + "</Privilege>\r\n";
	XmlTimeSet += "</Notify>\r\n";
	XmlTimeSet += "</Action>\r\n";
	char *xml = new char[XMLSIZE];
	memset(xml, 0, XMLSIZE);
	strcpy(xml, XmlTimeSet.c_str());
	CSipMsgProcess *Sip = new CSipMsgProcess;
	char *SipXml = new char[MAXBUFSIZE];
	memset(SipXml, 0, MAXBUFSIZE);
	Sip->SipXmlMsg(&SipXml, pWnd->m_InfoServer, pWnd->m_InfoClient, xml);
	//send message to client
	if (pWnd->m_InfoServer.Port == "" || pWnd->m_InfoServer.IP == "")
	{
		delete SipXml;
		delete xml;
		MessageBox("服务端IP和端口出错", "UAC 出错", MB_OK | MB_ICONERROR);
		return;
	}
	UA_Msg uac_sendtemp;
	strcpy(uac_sendtemp.data, SipXml);
	EnterCriticalSection(&g_uac);
	uac_sendqueue.push(uac_sendtemp);
	LeaveCriticalSection(&g_uac);
	delete SipXml;
	delete xml;
	//update log
	pWnd->ShowTestLogData = "DO -------->\r\n";
	pWnd->ShowTestLogTitle = "Time Set Test";
	pWnd->CurStatusID.nSataus = TimeGet;
}
