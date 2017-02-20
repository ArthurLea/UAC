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
}


BEGIN_MESSAGE_MAP(CAlarm, CDialog)
	ON_BN_CLICKED(IDC_BTN_ALARM_NOTIFY, &CAlarm::OnBnClickedBtnAlarmNotify)
	ON_BN_CLICKED(IDC_BTN_TIMESET, &CAlarm::OnBnClickedBtnTimeset)
	ON_BN_CLICKED(IDC_BTN_ALARM_CANCEL, &CAlarm::OnBnClickedBtnAlarmCancel)
	ON_BN_CLICKED(IDC_BTN_ALARM_NOTIFY3, &CAlarm::OnBnClickedBtnAlarmNotify3)
END_MESSAGE_MAP()


// CAlarm message handlers

void CAlarm::OnBnClickedBtnAlarmNotify()
{
	// TODO: Add your control notification handler code here
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	//get information and create XML message	
	string XmlAlarm;
	XmlAlarm="<?xml version=\"1.0\"?>\r\n";
	XmlAlarm+="<Action>\r\n";
	//XmlAlarm+="<Notify>\r\n";
	XmlAlarm+="<Variable>AlarmNotify</Variable>\r\n";
	//	<Status>告警状态</Status> 
		//<Data>告警数据</Data> 
		//<BeginTime>告警发生时间</BeginTime> 
// 	XmlAlarm+="<Level>";
// 	XmlAlarm+=pWnd->m_InfoAlarm.Level;
// 	XmlAlarm+="</Level>\r\n";
	XmlAlarm+="<AlarmType>";
	XmlAlarm+=pWnd->m_InfoAlarm.AlarmType;
	XmlAlarm+="</AlarmType>\r\n";
	XmlAlarm+="<Address>";
	XmlAlarm+=pWnd->m_InfoAlarm.Address;
	XmlAlarm+="</Address>\r\n";	

	XmlAlarm+="<Status>video lost";
	//XmlAlarm+=pWnd->m_InfoAlarm.AlarmType;
	XmlAlarm+="</Status>\r\n";
	XmlAlarm+="<Data>5";
	//XmlAlarm+=pWnd->m_InfoAlarm.Address;
	XmlAlarm+="</Data>\r\n";	
	XmlAlarm+="<BeginTime>20140903T000000Z";
	//XmlAlarm+=pWnd->m_InfoAlarm.Address;
	XmlAlarm+="</BeginTime>\r\n";
	//XmlAlarm+="</Notify>\r\n";
	XmlAlarm+="</Action>\r\n";	
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
	// TODO: 在此添加控件通知处理程序代码
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	//get information and create XML message	
	string XmlAlarm;
	XmlAlarm="<?xml version=\"1.0\"?>\r\n";
	XmlAlarm+="<Action>\r\n";
	//XmlAlarm+="<Notify>\r\n";
	XmlAlarm+="<Variable>AlarmNotify</Variable>\r\n";
	//	<Status>告警状态</Status> 
	//<Data>告警数据</Data> 
	//<BeginTime>告警发生时间</BeginTime> 
	// 	XmlAlarm+="<Level>";
	// 	XmlAlarm+=pWnd->m_InfoAlarm.Level;
	// 	XmlAlarm+="</Level>\r\n";
	XmlAlarm+="<AlarmType>";
	XmlAlarm+=pWnd->m_InfoAlarm.AlarmType;
	XmlAlarm+="</AlarmType>\r\n";
	XmlAlarm+="<Address>";
	XmlAlarm+=pWnd->m_InfoAlarm.Address;
	XmlAlarm+="</Address>\r\n";	

	XmlAlarm+="<Status>video lost";
	//XmlAlarm+=pWnd->m_InfoAlarm.AlarmType;
	XmlAlarm+="</Status>\r\n";
	XmlAlarm+="<Data>5";
	//XmlAlarm+=pWnd->m_InfoAlarm.Address;
	XmlAlarm+="</Data>\r\n";	
	XmlAlarm+="<BeginTime>20140903T000000Z";
	//XmlAlarm+=pWnd->m_InfoAlarm.Address;
	XmlAlarm+="</BeginTime>\r\n";
	//XmlAlarm+="</Notify>\r\n";
	XmlAlarm+="</Action>\r\n";	
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
	// TODO: 在此添加控件通知处理程序代码
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	//get information and create XML message	
	string XmlAlarm;
	XmlAlarm="<?xml version=\"1.0\"?>\r\n";
	XmlAlarm+="<Action>\r\n";
	//XmlAlarm+="<Notify>\r\n";
	XmlAlarm+="<Variable>AlarmNotify</Variable>\r\n";
	//	<Status>告警状态</Status> 
	//<Data>告警数据</Data> 
	//<BeginTime>告警发生时间</BeginTime> 
	// 	XmlAlarm+="<Level>";
	// 	XmlAlarm+=pWnd->m_InfoAlarm.Level;
	// 	XmlAlarm+="</Level>\r\n";
	XmlAlarm+="<AlarmType>";
	XmlAlarm+=pWnd->m_InfoAlarm.AlarmType;
	XmlAlarm+="</AlarmType>\r\n";
	XmlAlarm+="<Address>";
	XmlAlarm+=pWnd->m_InfoAlarm.Address;
	XmlAlarm+="</Address>\r\n";	

	XmlAlarm+="<Status>video lost";
	//XmlAlarm+=pWnd->m_InfoAlarm.AlarmType;
	XmlAlarm+="</Status>\r\n";
	XmlAlarm+="<Data>5";
	//XmlAlarm+=pWnd->m_InfoAlarm.Address;
	XmlAlarm+="</Data>\r\n";	
	XmlAlarm+="<BeginTime>20140903T000000Z";
	//XmlAlarm+=pWnd->m_InfoAlarm.Address;
	XmlAlarm+="</BeginTime>\r\n";
	//XmlAlarm+="</Notify>\r\n";
	XmlAlarm+="</Action>\r\n";	
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
