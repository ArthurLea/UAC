// Alarm.cpp : implementation file
//

#include "stdafx.h"
#include "UAC.h"
#include "Alarm.h"
#include "UACDlg.h"
extern queue<UA_Msg> uac_sendqueue;
extern CRITICAL_SECTION g_uac;

// CAlarm dialog

IMPLEMENT_DYNAMIC(CAlarm, CDialog)

CAlarm::CAlarm(CWnd* pParent /*=NULL*/)
	: CDialog(CAlarm::IDD, pParent)
{

}

CAlarm::~CAlarm()
{
}

void CAlarm::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO4, m_selAddress);
	DDX_Control(pDX, IDC_COMBO_ALARMTYPENAME, m_AlarmTypeSel);
}

BOOL CAlarm::OnInitDialog()
{
	CDialog::OnInitDialog();

	arrAlarmType.push_back("1");
	m_AlarmTypeSel.InsertString(0, "高温报警");

	arrAlarmType.push_back("2");
	m_AlarmTypeSel.InsertString(1, "低温报警");

	arrAlarmType.push_back("3");
	m_AlarmTypeSel.InsertString(2, "视频丢失报警");

	arrAlarmType.push_back("4");
	m_AlarmTypeSel.InsertString(3, "移动侦测报警");

	arrAlarmType.push_back("5");
	m_AlarmTypeSel.InsertString(4, "遮挡侦测报警");

	arrAlarmType.push_back("6");
	m_AlarmTypeSel.InsertString(5, "输入开关量报警");

	m_AlarmTypeSel.SetCurSel(0);
	GetDlgItem(IDC_ALARMTYPENUM)->SetWindowTextA("1");

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}

BEGIN_MESSAGE_MAP(CAlarm, CDialog)
	ON_BN_CLICKED(IDC_BTN_TIMESET, &CAlarm::OnBnClickedBtnTimeset)
	ON_BN_CLICKED(IDC_BTN_ALARM_CANCEL, &CAlarm::OnBnClickedBtnAlarmCancel)
	ON_BN_CLICKED(IDC_BTN_ALARM_NOTIFY3, &CAlarm::OnBnClickedBtnAlarmNotify3)
END_MESSAGE_MAP()


// CAlarm message handlers

void CAlarm::OnBnClickedBtnTimeset()
{
	// TODO: Add your control notification handler code here
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	//get information and create XML message	
	string XmlTimeSet;
	XmlTimeSet="<?xml version=\"1.0\"?>\r\n";
	XmlTimeSet+="<Action>\r\n";
	XmlTimeSet+="<Notify>\r\n";
	XmlTimeSet+="<Variable>TimeGet</Variable>\r\n";	
	XmlTimeSet+="<Privilege>0100100001</Privilege>\r\n";	
	XmlTimeSet+="</Notify>\r\n";
	XmlTimeSet+="</Action>\r\n";	
	char *xml=new char[XMLSIZE];
	memset(xml,0,XMLSIZE);
	strcpy(xml,XmlTimeSet.c_str());
	CSipMsgProcess *Sip=new CSipMsgProcess;
	char *SipXml=new char[MAXBUFSIZE];
	memset(SipXml,0,MAXBUFSIZE);
	Sip->SipXmlMsg(&SipXml,pWnd->m_InfoServer,pWnd->m_InfoClient,xml);
	//send message to client
	if (pWnd->m_InfoServer.Port=="" || pWnd->m_InfoServer.IP=="")
	{	
		delete SipXml;
		delete xml;
		MessageBox("服务端IP和端口出错","UAC 出错",MB_OK|MB_ICONERROR);		
		return;
	}	
	//pWnd->SendData(SipXmlAlarm);
	UA_Msg uac_sendtemp;
	strcpy(uac_sendtemp.data,SipXml);
	EnterCriticalSection(&g_uac);
	uac_sendqueue.push(uac_sendtemp);
	LeaveCriticalSection(&g_uac);
	//pWnd->ShowSendData(SipXmlAlarm);	
	delete SipXml;
	delete xml;
	//update log
	pWnd->ShowTestLogData="DO -------->\r\n";
	pWnd->ShowTestLogTitle="Time Set Test";
	pWnd->CurStatusID.nSataus=TimeGet;

}

void CAlarm::OnBnClickedBtnAlarmCancel()
{
	HWND   hnd = ::FindWindow(NULL, _T("UAC"));
	CUACDlg*  pWnd = (CUACDlg*)CWnd::FromHandle(hnd);
	//Create XML message
	//CString UserCode;
	CString Level;
	CString AlarmType;
	CString Address;
	//CString AcceptIP;
	//CString AcceptPort;
	//GetDlgItem(IDC_EDIT_PRIVILEGE)->GetWindowText(UserCode);
	GetDlgItem(IDC_EDIT_LEVEL)->GetWindowText(Level);
	GetDlgItem(IDC_ALARMTYPENUM)->GetWindowText(AlarmType);
	GetDlgItem(IDC_EDIT_ADDRESS)->GetWindowText(Address);
	//GetDlgItem(IDC_EDIT_ACCEPTIP)->GetWindowText(AcceptIP);
	//GetDlgItem(IDC_EDIT_ACCEPTPORT)->GetWindowText(AcceptPort);
	//get information and create XML message	
	//string XmlAlarm;
	//XmlAlarm = "<?xml version=\"1.0\"?>\r\n";
	//XmlAlarm += "<Action>\r\n";
	//XmlAlarm+="<Notify>\r\n";
	//XmlAlarm += "<Variable>AlarmNotify</Variable>\r\n";
	//	<Status>告警状态</Status> 
	// <Data>告警数据</Data> 
	// <BeginTime>告警发生时间</BeginTime> 
	// 	XmlAlarm+="<Level>";
	// 	XmlAlarm+=pWnd->m_InfoAlarm.Level;
	// 	XmlAlarm+="</Level>\r\n";
	//XmlAlarm += "<AlarmType>";
	//XmlAlarm += pWnd->m_InfoAlarm.AlarmType;
	//XmlAlarm += "</AlarmType>\r\n";
	//XmlAlarm += "<Address>";
	//XmlAlarm += pWnd->m_InfoAlarm.Address;
	//XmlAlarm += "</Address>\r\n";
	//XmlAlarm += "<Status>video lost";
	//XmlAlarm += pWnd->m_InfoAlarm.AlarmType;
	//XmlAlarm += "</Status>\r\n";
	//XmlAlarm += "<Data>5";
	//XmlAlarm += pWnd->m_InfoAlarm.Address;
	//XmlAlarm += "</Data>\r\n";
	//XmlAlarm += "<BeginTime>20140903T000000Z";
	//XmlAlarm += pWnd->m_InfoAlarm.Address;
	//XmlAlarm += "</BeginTime>\r\n";
	//XmlAlarm += "</Notify>\r\n";
	//XmlAlarm += "</Action>\r\n";
	string XmlAlarm;
	XmlAlarm = "<?xml version=\"1.0\"?>\r\n";
	XmlAlarm += "<Action>\r\n";
	XmlAlarm += "<Notify>\r\n";
	XmlAlarm += "<Variable>AlarmNotify</Variable>\r\n";
	//XmlAlarm += "<Privilege>" + UserCode + "</Privilege>\r\n";
	XmlAlarm += "<Address>" + Address + "</Address>\r\n";
	XmlAlarm += "<Level>" + Level + "</Level>\r\n";
	XmlAlarm += "<AlarmType>" + AlarmType + "</AlarmType>\r\n";
	//XmlAlarm += "<AcceptIp>" + AcceptIP + "</AcceptIp>\r\n";
	//XmlAlarm += "<AcceptPort>" + AcceptPort + "</AcceptPort>\r\n";
	XmlAlarm += "</Notify>\r\n";
	XmlAlarm += "</Action>\r\n";

	char *xml=new char[XMLSIZE];
	memset(xml,0,XMLSIZE);
	strcpy(xml,XmlAlarm.c_str());
	CSipMsgProcess *SipAlarm=new CSipMsgProcess;
	char *SipXmlAlarm=new char[MAXBUFSIZE];
	memset(SipXmlAlarm,0,MAXBUFSIZE);
	SipAlarm->SipAlarmNotifyXmlMsg(&SipXmlAlarm,pWnd->m_InfoServer,pWnd->m_InfoClient,xml);
	//send message to client
	if (pWnd->m_InfoServer.Port=="" || pWnd->m_InfoServer.IP=="")
	{	
		delete SipXmlAlarm;
		delete xml;
		MessageBox("服务端IP和端口出错","UAC 出错",MB_OK|MB_ICONERROR);		
		return;
	}	
	//pWnd->SendData(SipXmlAlarm);
	UA_Msg uac_sendtemp;
	strcpy(uac_sendtemp.data,SipXmlAlarm);
	EnterCriticalSection(&g_uac);
	uac_sendqueue.push(uac_sendtemp);
	LeaveCriticalSection(&g_uac);
	//pWnd->ShowSendData(SipXmlAlarm);	
	delete SipXmlAlarm;
	delete xml;
	//update log
	pWnd->ShowTestLogData="NOTIFY -------->\r\n";
	pWnd->ShowTestLogTitle="AlarmNotify Send Test";
	pWnd->CurStatusID.nSataus=Alarm;
}

void CAlarm::OnBnClickedBtnAlarmNotify3()
{
	HWND   hnd = ::FindWindow(NULL, _T("UAC"));
	CUACDlg*  pWnd = (CUACDlg*)CWnd::FromHandle(hnd);
	//Create XML message
	//CString UserCode;
	CString Level;
	CString AlarmType;
	CString Address;
	//CString AcceptIP;
	//CString AcceptPort;
	//GetDlgItem(IDC_EDIT_PRIVILEGE)->GetWindowText(UserCode);
	GetDlgItem(IDC_EDIT_LEVEL)->GetWindowText(Level);
	GetDlgItem(IDC_ALARMTYPENUM)->GetWindowText(AlarmType);
	GetDlgItem(IDC_EDIT_ADDRESS)->GetWindowText(Address);
	//GetDlgItem(IDC_EDIT_ACCEPTIP)->GetWindowText(AcceptIP);
	//GetDlgItem(IDC_EDIT_ACCEPTPORT)->GetWindowText(AcceptPort);

	//get information and create XML message	
	//string XmlAlarm;
	//XmlAlarm = "<?xml version=\"1.0\"?>\r\n";
	//XmlAlarm += "<Action>\r\n";
	//XmlAlarm+="<Notify>\r\n";
	//XmlAlarm += "<Variable>AlarmNotify</Variable>\r\n";
	//	<Status>告警状态</Status> 
	// <Data>告警数据</Data> 
	// <BeginTime>告警发生时间</BeginTime> 
	// 	XmlAlarm+="<Level>";
	// 	XmlAlarm+=pWnd->m_InfoAlarm.Level;
	// 	XmlAlarm+="</Level>\r\n";
	//XmlAlarm += "<AlarmType>";
	//XmlAlarm += pWnd->m_InfoAlarm.AlarmType;
	//XmlAlarm += "</AlarmType>\r\n";
	//XmlAlarm += "<Address>";
	//XmlAlarm += pWnd->m_InfoAlarm.Address;
	//XmlAlarm += "</Address>\r\n";
	//XmlAlarm += "<Status>video lost";
	//XmlAlarm += pWnd->m_InfoAlarm.AlarmType;
	//XmlAlarm += "</Status>\r\n";
	//XmlAlarm += "<Data>5";
	//XmlAlarm += pWnd->m_InfoAlarm.Address;
	//XmlAlarm += "</Data>\r\n";
	//XmlAlarm += "<BeginTime>20140903T000000Z";
	//XmlAlarm += pWnd->m_InfoAlarm.Address;
	//XmlAlarm += "</BeginTime>\r\n";
	//XmlAlarm += "</Notify>\r\n";
	//XmlAlarm += "</Action>\r\n";
	string XmlAlarm;
	XmlAlarm = "<?xml version=\"1.0\"?>\r\n";
	XmlAlarm += "<Action>\r\n";
	XmlAlarm += "<Notify>\r\n";
	XmlAlarm += "<Variable>AlarmNotify</Variable>\r\n";
	//XmlAlarm += "<Privilege>" + UserCode + "</Privilege>\r\n";
	XmlAlarm += "<Address>" + Address + "</Address>\r\n";
	XmlAlarm += "<Level>" + Level + "</Level>\r\n";
	XmlAlarm += "<AlarmType>" + AlarmType + "</AlarmType>\r\n";
	//XmlAlarm += "<AcceptIp>" + AcceptIP + "</AcceptIp>\r\n";
	//XmlAlarm += "<AcceptPort>" + AcceptPort + "</AcceptPort>\r\n";
	XmlAlarm += "</Notify>\r\n";
	XmlAlarm += "</Action>\r\n";

	char *xml = new char[XMLSIZE];
	memset(xml, 0, XMLSIZE);
	strcpy(xml, XmlAlarm.c_str());
	CSipMsgProcess *SipAlarm = new CSipMsgProcess;
	char *SipXmlAlarm = new char[MAXBUFSIZE];
	memset(SipXmlAlarm, 0, MAXBUFSIZE);
	SipAlarm->SipAlarmNotifyXmlMsg(&SipXmlAlarm, pWnd->m_InfoServer, pWnd->m_InfoClient, xml);
	//send message to client
	if (pWnd->m_InfoServer.Port == "" || pWnd->m_InfoServer.IP == "")
	{
		delete SipXmlAlarm;
		delete xml;
		MessageBox("服务端IP和端口出错", "UAC 出错", MB_OK | MB_ICONERROR);
		return;
	}
	UA_Msg uac_sendtemp;
	strcpy(uac_sendtemp.data, SipXmlAlarm);
	EnterCriticalSection(&g_uac);
	uac_sendqueue.push(uac_sendtemp);
	LeaveCriticalSection(&g_uac);
	delete SipXmlAlarm;
	delete xml;
	//update log
	pWnd->ShowTestLogData = "NOTIFY -------->\r\n";
	pWnd->ShowTestLogTitle = "AlarmNotify Send Test";
	pWnd->CurStatusID.nSataus = Alarm;
}
