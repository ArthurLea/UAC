// Invite.cpp : implementation file
//

#include "stdafx.h"
#include "UAC.h"
#include "Invite.h"
#include "UACDlg.h"
extern queue<UA_Msg> uac_sendqueue;
extern CRITICAL_SECTION g_uac;


// CInvite dialog

IMPLEMENT_DYNAMIC(CInvite, CDialog)

CInvite::CInvite(CWnd* pParent /*=NULL*/)
	: CDialog(CInvite::IDD, pParent)
{

}

CInvite::~CInvite()
{
}

void CInvite::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_ADDRESS, m_address);
}


BEGIN_MESSAGE_MAP(CInvite, CDialog)
	ON_BN_CLICKED(IDC_BTN_BYE, &CInvite::OnBnClickedBtnBye)
	ON_BN_CLICKED(IDC_BUTTON1, &CInvite::OnBnClickedButton1)
END_MESSAGE_MAP()


// CInvite message handlers

void CInvite::OnBnClickedBtnBye()
{
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	UA_Msg uac_sendtemp;
	strcpy(uac_sendtemp.data,pWnd->byestring);
	EnterCriticalSection(&g_uac);
	uac_sendqueue.push(uac_sendtemp);
	LeaveCriticalSection(&g_uac);	
	//update log
	pWnd->ShowTestLogData="BYE -------->\r\n";
	pWnd->ShowTestLogTitle="Invite Test";
	pWnd->m_Invite.GetDlgItem(IDC_BTN_BYE)->EnableWindow(FALSE);
}


void CInvite::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	CString adress;
	CString name;
	CString operate;
	CString privilege;
	CString status;
	GetDlgItem(IDC_ADDRESS)->GetWindowTextA(adress);
	GetDlgItem(IDC_NAME)->GetWindowTextA(name);
	GetDlgItem(IDC_OPERATE)->GetWindowTextA(operate);
	GetDlgItem(IDC_PRIVILEGE)->GetWindowTextA(privilege);
	GetDlgItem(IDC_STATUS)->GetWindowTextA(status);
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	pWnd->ShowRecvData("\t\t-----注册成功-----\r\n");
	pWnd->ShowTestLogData+="<------------ 200 OK\r\n";				
	char *dst=new char[XMLSIZE];				
	char *dstNodeMsg=new char[MAXBUFSIZE];
	//CSipMsgProcess sip;
	//sip.XmlNodeCreate(&dst);//产生推送消息
	CString strTemp;
	strTemp="<?xml version=\"1.0\"?>\r\n";
	strTemp+="<Action>\r\n";
	strTemp+="<CmdType>Catalog</CmdType>\r\n";
	strTemp+="<Parent>"+pWnd->m_InfoClient.UserAddress+"</Parent>\r\n";	
	strTemp+="<TotalSubNum>10</TotalSubNum>\r\n";
	strTemp+="<TotalOnlineSubNum>2</TotalOnlineSubNum>\r\n";
	strTemp+="<SubNum>2</SubNum>\r\n";
	strTemp+="<SubList>\r\n";
	strTemp+="<Item>\r\n";
	strTemp+="<Name>DVS01</Name>\r\n";
	strTemp+="<Address>200200101100000002</Address>\r\n";
	strTemp+="<ResType>2</ResType>\r\n";
	strTemp+="<ResSubType>3</ResSubType>\r\n";
	strTemp+="<Privilege>20020010119000001</Privilege>\r\n";
	//strTemp+="<SeriesNumber>000000000123</SeriesNumber>\r\n";
	strTemp+="<Status>"+status+"</Status>\r\n";
	strTemp+="<Longitude>10</Longitude>\r\n";
	strTemp+="<Latitude>10</Latitude>\r\n";
	strTemp+="<Elevation>10</Elevation>\r\n";	
	strTemp+="<Roadway>10</Roadway>\r\n";
	strTemp+="<PileNo>10</PileNo>\r\n";
	strTemp+="<AreaNo>1</AreaNo>\r\n";
	//strTemp+="<DecoderTag>H3C</DecoderTag>\r\n";
	strTemp+="<OperateType>"+operate+"</OperateType>\r\n";
	strTemp+="<UpdateTime>20051110T133050Z</UpdateTime>\r\n";	
	strTemp+="</Item>\r\n";
	strTemp+="</SubList>\r\n";
	strTemp+="</Action>\r\n";	
	//char *str=(LPSTR)(LPCTSTR)strTemp;
	CSipMsgProcess *sip;
	sip=new CSipMsgProcess;
	//sip->SipNodeXmlMsg(&dstNodeMsg,pWnd->m_InfoServer,pWnd->m_InfoClient,strTemp.GetBuffer(strTemp.GetLength()));	
	sip->SipNotifyXmlMsg(&dstNodeMsg,pWnd->m_InfoServer,pWnd->m_InfoClient,strTemp.GetBuffer(strTemp.GetLength()));
	//pWnd->SendData(dstNodeMsg);
	UA_Msg uac_sendtemp;
	strcpy(uac_sendtemp.data,dstNodeMsg);
	EnterCriticalSection(&g_uac);
	uac_sendqueue.push(uac_sendtemp);
	LeaveCriticalSection(&g_uac);
	//pWnd->ShowSendData(dstNodeMsg);
	delete dst;					
	delete dstNodeMsg;			

// 	strcpy(uac_sendtemp.data,pWnd->byestring);
// 	EnterCriticalSection(&g_uac);
// 	uac_sendqueue.push(uac_sendtemp);
// 	LeaveCriticalSection(&g_uac);	
	//update log
	pWnd->ShowTestLogData="BYE -------->\r\n";
	pWnd->ShowTestLogTitle="Invite Test";
	//delete sip;
}
