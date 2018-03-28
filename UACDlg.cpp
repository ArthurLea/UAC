// UACDlg.cpp : ʵ���ļ�
//
#include "stdafx.h"
#include "UAC.h"
#include "UACDlg.h"
#include <fstream>
using namespace std;
ofstream uac_msg_log;
CRITICAL_SECTION g_uac;
HANDLE h_UAC_Recv;
HANDLE h_UAC_Dispatch;
HANDLE h_UAC_Send;
queue<UA_Msg> uac_recvqueue;
queue<UA_Msg> uac_sendqueue;
UA_Msg uac_curqueue;
UA_Msg uac_curSendMsg;
static char ProcessIP[50]={0};
static char m_SendIP[16]={0};
vector<CString> HistoryVideoList;
vector<CString> PresetInfoList;
InfoNotify NotifyInfo;
struct Authenticate g_authInfo;
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()

// CUACDlg �Ի���
CUACDlg::CUACDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CUACDlg::IDD, pParent)
	, m_bIsShowKeepAliveMsg(false)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CUACDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TAB, m_Ctab);
	DDX_Control(pDX, IDC_BOX_TESTMEMBER, m_TestMember);
	DDX_Control(pDX, IDC_EDT_SENDMSG, m_ShowSendMsg);
	DDX_Control(pDX, IDC_EDT_RECVMSG, m_ShowRecvMsg);
	DDX_Control(pDX, IDC_COMBO1, m_IpGroup);
}

BEGIN_MESSAGE_MAP(CUACDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	//�Զ�����Ϣ
	ON_MESSAGE(WM_RECVDATA,RecvData)
	ON_MESSAGE(WM_SENDDATA,SendMsgData)
	ON_MESSAGE(WM_RECEIVE, OnReceive)
	ON_MESSAGE(WM_CLIENTCLOSE, OnClientClose)
	ON_MESSAGE(WM_ACCEPT, OnAccept)
	ON_NOTIFY(TCN_SELCHANGE, IDC_TAB, &CUACDlg::OnTcnSelchangeTab)
	ON_BN_CLICKED(IDC_BTN_SEND_CLEAR, &CUACDlg::OnBnClickedBtnSendClear)
	ON_BN_CLICKED(IDC_BTN_RECV_CLEAR, &CUACDlg::OnBnClickedBtnRecvClear)
	ON_BN_CLICKED(IDC_BTN_SIP_REGISTER, &CUACDlg::OnBnClickedBtnSipRegister)
	ON_BN_CLICKED(IDC_BTN_SET, &CUACDlg::OnBnClickedBtnSet)
	ON_BN_CLICKED(IDC_BTN_LOG, &CUACDlg::OnBnClickedBtnLog)
	ON_WM_TIMER()
	ON_BN_CLICKED(IDCANCEL, &CUACDlg::OnBnClickedCancel)
	ON_CBN_SELCHANGE(IDC_BOX_TESTMEMBER, &CUACDlg::OnCbnSelchangeBoxTestmember)
	ON_STN_CLICKED(IDC_SABOUT, &CUACDlg::OnStnClickedSabout)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CUACDlg::OnCbnSelchangeCombo1)
	ON_BN_CLICKED(IDC_BUTTON_REBOOT, &CUACDlg::OnBnClickedButtonReboot)
	ON_BN_CLICKED(IDC_CHECK1, &CUACDlg::OnBnClickedCheck1)
END_MESSAGE_MAP()

// CUACDlg ��Ϣ�������

BOOL CUACDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��
	CFont * f; 
	f = new CFont; 
	f->CreateFont(30,            // nHeight 
		10,           // nWidth 
		0,           // nEscapement 
		0,           // nOrientation 
		FW_BOLD,     // nWeight 
		FALSE,        // bItalic 
		FALSE,       // bUnderline 
		0,           // cStrikeOut 
		ANSI_CHARSET,              // nCharSet 
		OUT_DEFAULT_PRECIS,        // nOutPrecision 
		CLIP_DEFAULT_PRECIS,       // nClipPrecision 
		DEFAULT_QUALITY,           // nQuality 
		DEFAULT_PITCH | FF_SWISS, // nPitchAndFamily 
		_T("Arial"));              // lpszFac

	GetDlgItem(IDC_STATICMT)->SetFont(f);
	CFont * f2;
	f2 = new CFont;
	f2->CreateFont(14,            // nHeight 
		6,           // nWidth 
		0,           // nEscapement 
		0,           // nOrientation 
		FW_BOLD,     // nWeight 
		FALSE,        // bItalic 
		TRUE,       // bUnderline 
		0,           // cStrikeOut 
		ANSI_CHARSET,              // nCharSet 
		OUT_DEFAULT_PRECIS,        // nOutPrecision 
		CLIP_DEFAULT_PRECIS,       // nClipPrecision 
		DEFAULT_QUALITY,           // nQuality 
		DEFAULT_PITCH | FF_SWISS, // nPitchAndFamily 
		_T("����"));              // lpszFac
	GetDlgItem(IDC_SABOUT)->SetFont(f2);

	ifstream fin;
	fin.open("HistoryVideoList.xml");
	while(!fin.eof())
	{
		char t[500];
		fin>>t;
		HistoryVideoList.push_back(t);
	}
	fin.close();
	fin.open("PresetInfoList.xml");
	while(!fin.eof())
	{
		char t[500];
		fin>>t;
		PresetInfoList.push_back(t);
	}
	fin.close();
	GetDlgItem(IDC_USERNAMEC)->SetWindowText("client_user");
	GetDlgItem(IDC_PASSWORDC)->SetWindowText("123456");
	uac_msg_log.open("uac_msg.log");
	InitProgram();
	InitNetSet();
	InitAlarm();
	InitEnableWindow();
	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CUACDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�
void CUACDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CUACDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CUACDlg::InitProgram()
{
	//��ʼ�������б���Ͽ�
	FILE *TestMemberFile=NULL;
	TestMemberFile=fopen("���Գ����б�.txt","r");	
	char *temp=new char[40];
	char *temp1=new char[40];
	int i=0;
	ProductMember test;	
	if (TestMemberFile!=NULL)
	{
		while (1)
		{
			if(feof(TestMemberFile))
				break;
			fscanf(TestMemberFile,"%s\n",temp);
			fscanf(TestMemberFile,"%s\n",temp1);
			strcpy(test.IP,temp1);
			ProductTestMember.push_back(test);
			m_TestMember.InsertString(i,temp);
			i++;			
		}
	} 
	else
	{
		TestMemberFile=fopen("���Գ����б�.txt","w");
		m_TestMember.AddString("��������");
		fprintf(TestMemberFile,"��������");
		fprintf(TestMemberFile,"\n192.168.1.100");
		strcpy(test.IP,"192.168.1.100");
		ProductTestMember.push_back(test);
		m_TestMember.AddString("H3C");
		fprintf(TestMemberFile,"\nH3C");
		fprintf(TestMemberFile,"\n192.168.1.111");
		strcpy(test.IP,"192.168.1.111");
		ProductTestMember.push_back(test);
		m_TestMember.AddString("�人΢�����");
		fprintf(TestMemberFile,"\n�人΢�����");
		fprintf(TestMemberFile,"\n192.168.1.50");
		strcpy(test.IP,"192.168.1.50");
		ProductTestMember.push_back(test);
		m_TestMember.AddString("����ƹ�");
		fprintf(TestMemberFile,"\n����ƹ�");
		fprintf(TestMemberFile,"\n192.168.1.43");
		strcpy(test.IP,"192.168.1.43");
		ProductTestMember.push_back(test);
		m_TestMember.AddString("�����ǰ�");
		fprintf(TestMemberFile,"\n�����ǰ�");
		fprintf(TestMemberFile,"\n192.168.1.30");
		strcpy(test.IP,"192.168.1.30");
		ProductTestMember.push_back(test);
		m_TestMember.AddString("��������");
		fprintf(TestMemberFile,"\n��������");
		fprintf(TestMemberFile,"\n192.168.1.20");
		strcpy(test.IP,"192.168.1.20");
		ProductTestMember.push_back(test);
		m_TestMember.AddString("��������");
		fprintf(TestMemberFile,"\n��������");
		fprintf(TestMemberFile,"\n192.168.1.73");
		strcpy(test.IP,"192.168.1.73");
		ProductTestMember.push_back(test);
	}	
	m_TestMember.SetCurSel(0);
	strcpy(ProcessIP,ProductTestMember[0].IP);
	if (TestMemberFile)
	{
		fclose(TestMemberFile);
	}
	delete []temp;
	delete []temp1;
	//��ʼ����ǩҳ
	m_Ctab.InsertItem(0,_T("��������"));
	m_Ctab.InsertItem(1,_T("ʵʱ��"));
	m_Ctab.InsertItem(2,_T("��̨����"));
	m_Ctab.InsertItem(3,_T("��Ƶ��ѯ"));
	m_Ctab.InsertItem(4,_T("��Ƶ�ط�"));
	m_Ctab.InsertItem(5,_T("��������"));
	m_Ctab.InsertItem(6,_T("����������")); 
	m_Ctab.InsertItem(7,_T("ʱ������У��")); 
	//Ϊ��ǩҳ��ӳ�ʼ���Ի���
	m_NetSet.Create(IDD_DLG_NETSET,GetDlgItem(IDC_TAB));
	m_Invite.Create(IDD_DLG_INVITE,GetDlgItem(IDC_TAB));
	m_PTZ.Create(IDD_DLG_PTZ,GetDlgItem(IDC_TAB));
	m_VideoQuery.Create(IDD_DLG_VIDEOQUERY,GetDlgItem(IDC_TAB));
	m_VideoPlay.Create(IDD_DLG_VIDEOPLAY,GetDlgItem(IDC_TAB));
	m_CoderSet.Create(IDD_DLG_CODER_SET,GetDlgItem(IDC_TAB));
	m_Alarm.Create(IDD_DLG_ALARM,GetDlgItem(IDC_TAB));
	m_PSTVSetTime.Create(IDD_DLG_PSTVTIME,GetDlgItem(IDC_TAB));
	//���IDC_TAB�ͻ�����С
	CRect rect;
	m_Ctab.GetClientRect(&rect);	
	//�����ӶԻ����ڸ������е�λ�ã����ԸĶ���ֵ��ʹ�Ӵ���Ĵ�С����
	rect.top+=22;
	rect.bottom-=3;
	rect.left+=2;
	rect.right-=4;
	//�����ӶԻ���ߴ粢�ƶ���ָ��λ��
	m_NetSet.MoveWindow(&rect);
	m_Invite.MoveWindow(&rect);
	m_PTZ.MoveWindow(&rect);
	m_VideoQuery.MoveWindow(&rect);
	m_VideoPlay.MoveWindow(&rect);
	m_CoderSet.MoveWindow(&rect);
	m_Alarm.MoveWindow(&rect);
	m_PSTVSetTime.MoveWindow(&rect);
	//�ֱ��������غ���ʾ
	m_NetSet.ShowWindow(true);
	//����Ĭ�ϵ�ѡ�
	m_Ctab.SetCurSel(0);
	bSipRegister=FALSE;
	bNodeType=FALSE;
	bACK=  FALSE;
	bBYE = FALSE;	
	CurStatusID.nSataus=99;
	bShowRealTime=FALSE;
	m_TCPSocket.Initialize(this);
	bKeepAlive=FALSE;
	bRealTimeFlag=FALSE;
	nRealTimeCount=0;
	nKeepTimeCount=0;
	nRstpTimeCount=0;
	contact=NULL;	
	brtspKeeplive=FALSE;
	bRtspLive=FALSE;
	bRtspLiveFlag=FALSE;
	contact=new char[100];
	byestring=new char[MAXBUFSIZE];	
	balarmsubscribe=FALSE;
	memset(invite100tag,0,50);
	memset(alarmFromTag, 0, 50);
	memset(alarmToTag,0,50);
	nKeepCseq=1;
}

void CUACDlg::OnTcnSelchangeTab(NMHDR *pNMHDR, LRESULT *pResult)
{
	int CurSel = m_Ctab.GetCurSel();
	switch(CurSel)
	{
	case 0:
		m_NetSet.ShowWindow(true);
		m_Invite.ShowWindow(false);
		m_PTZ.ShowWindow(false);
		m_VideoQuery.ShowWindow(false);
		m_VideoPlay.ShowWindow(false);
		m_CoderSet.ShowWindow(false);	
		m_Alarm.ShowWindow(false); 	
		m_PSTVSetTime.ShowWindow(false);
		break;
	case 1:		
		m_NetSet.ShowWindow(false);
		m_Invite.ShowWindow(true);
		m_PTZ.ShowWindow(false);
		m_VideoQuery.ShowWindow(false);
		m_VideoPlay.ShowWindow(false);
		m_CoderSet.ShowWindow(false);	
		m_Alarm.ShowWindow(false);
		m_PSTVSetTime.ShowWindow(false);
		break;
	case 2:	
		m_NetSet.ShowWindow(false);
		m_Invite.ShowWindow(false);
		m_PTZ.ShowWindow(true);
		m_VideoQuery.ShowWindow(false);
		m_VideoPlay.ShowWindow(false);
		m_CoderSet.ShowWindow(false);	
		m_Alarm.ShowWindow(false);
		m_PSTVSetTime.ShowWindow(false);
		break;
	case 3:	
		m_NetSet.ShowWindow(false);
		m_Invite.ShowWindow(false);
		m_PTZ.ShowWindow(false);
		m_VideoQuery.ShowWindow(true);
		m_VideoPlay.ShowWindow(false);
		m_CoderSet.ShowWindow(false);	
		m_Alarm.ShowWindow(false);
		m_PSTVSetTime.ShowWindow(false);
		break;
	case 4:	
		m_NetSet.ShowWindow(false);
		m_Invite.ShowWindow(false);
		m_PTZ.ShowWindow(false);
		m_VideoQuery.ShowWindow(false);
		m_VideoPlay.ShowWindow(true);
		m_CoderSet.ShowWindow(false);	
		m_Alarm.ShowWindow(false);
		m_PSTVSetTime.ShowWindow(false);
		break;
	case 5:	
		m_NetSet.ShowWindow(false);
		m_Invite.ShowWindow(false);
		m_PTZ.ShowWindow(false);
		m_VideoQuery.ShowWindow(false);
		m_VideoPlay.ShowWindow(false);
		m_Alarm.ShowWindow(true);
		m_CoderSet.ShowWindow(false);
		m_PSTVSetTime.ShowWindow(false);
		break;	
	case 6:	
 		m_NetSet.ShowWindow(false);
 		m_Invite.ShowWindow(false);
 		m_PTZ.ShowWindow(false);
 		m_VideoQuery.ShowWindow(false);
 		m_VideoPlay.ShowWindow(false);
 		m_Alarm.ShowWindow(false);
 		m_CoderSet.ShowWindow(true);
		m_PSTVSetTime.ShowWindow(false);
 		break;
	case 7:
		m_NetSet.ShowWindow(false);
		m_Invite.ShowWindow(false);
		m_PTZ.ShowWindow(false);
		m_VideoQuery.ShowWindow(false);
		m_VideoPlay.ShowWindow(false);
		m_CoderSet.ShowWindow(false);
		m_Alarm.ShowWindow(false);
		m_PSTVSetTime.ShowWindow(true);
		break;
	default:
		break;
	} 
	*pResult = 0;
}

//��װ��Ա����--�Ƿ����û���ÿؼ�--Ĭ��Ϊ��״̬���ð�ť
BOOL CUACDlg::EnableWindow(UINT uID, BOOL bEnable=TRUE)
{
	return ::EnableWindow(GetDlgItem(uID)->GetSafeHwnd(), bEnable);
}

//��װ��Ա����--��ȡ���ؼ��������
int CUACDlg::GetLocalHostName(CString &sHostName)
{
	char szHostName[40];
	int nRetCode;
	nRetCode=gethostname(szHostName,sizeof(szHostName));
	if(nRetCode!=0)
	{		
		MessageBox("���ؼ�������ƻ�ȡʧ��","UAC ����",MB_OK|MB_ICONERROR);
		return GetLastError();
	}
	sHostName = szHostName;
	return 0;
}

//��װ��Ա����--��ȡ���ؼ����IP��ַ
int CUACDlg::GetLocalIp(const CString &sHostName, CString &sIpAddress)
{	
	//��CString����ת����char*
	int strLength = sHostName.GetLength() + 1;
	char *cHostName = new char[strLength];	
	strncpy(cHostName, sHostName, strLength);
	struct hostent FAR * lpHostEnt=gethostbyname(cHostName);
	if(lpHostEnt==NULL)
	{
		//��������
		MessageBox("���ؼ����IP��ַ��ȡʧ��","UAC ����",MB_OK|MB_ICONERROR);
		return GetLastError();
	}
	//��ȡIP��ַ
	LPSTR lpAddr=lpHostEnt->h_addr_list[0];

	if(lpAddr)
	{
		struct in_addr inAddr;
		memmove(&inAddr,lpAddr,4);
		//��ʽת��Ϊ��׼��ʽ
		sIpAddress=inet_ntoa(inAddr);
		m_IpGroup.InsertString(0,sIpAddress);
		if(sIpAddress.IsEmpty())
			MessageBox("���ؼ����IP��ַ��ȡʧ��","UAC ����",MB_OK|MB_ICONERROR);
	}

	lpAddr=lpHostEnt->h_addr_list[1];
	if(lpAddr)
	{
		struct in_addr inAddr;
		memmove(&inAddr,lpAddr,4);
		//��ʽת��Ϊ��׼��ʽ
		sIpAddress=inet_ntoa(inAddr);
		m_IpGroup.InsertString(1,sIpAddress);
		if(sIpAddress.IsEmpty())
			MessageBox("���ؼ����IP��ַ��ȡʧ��","UAC ����",MB_OK|MB_ICONERROR);
	}
	m_IpGroup.SetCurSel(0);  

	return 0;
}

//��ʼ������������Ϣ
void CUACDlg::InitNetSet()
{
	//���ó�ʼ������IP��ַ�Ͷ˿ڱ�������������Ϣ	
	CString LocalHostName;
	GetLocalHostName(LocalHostName);
	GetLocalIp(LocalHostName,m_InfoClient.IP);
	//��ʼ�����������ļ�
	FILE *NetFile=NULL;
	NetFile=fopen("UACNetLog.txt","r");	
	char *temp=new char[40];	
	if (NetFile!=NULL)
	{

		fscanf(NetFile,"%s\n",temp);	
		m_InfoClient.Port.Format("%s",temp);

		fscanf(NetFile,"%s\n",temp);	
		TCP_Port.Format("%s",temp);

		fscanf(NetFile,"%s\n",temp);	
		m_InfoClient.UserName.Format("%s",temp);

		fscanf(NetFile,"%s\n",temp);	
		m_InfoClient.UserAddress.Format("%s",temp);

		fscanf(NetFile,"%s\n",temp);	
		m_InfoServer.IP.Format("%s",temp);

		fscanf(NetFile,"%s\n",temp);	
		m_InfoServer.Port.Format("%s",temp);

		fscanf(NetFile,"%s\n",temp);	
		m_InfoServer.UserName.Format("%s",temp);

		fscanf(NetFile,"%s\n",temp);	
		m_InfoServer.UserAddress.Format("%s",temp);
	} 
	else
	{
		NetFile=fopen("UACNetLog.txt","w");
		m_InfoClient.Port="5060";	
		TCP_Port="5211";
		m_InfoClient.UserName="123";
		m_InfoClient.UserAddress="123";

		m_InfoServer.IP="192.168.9.89";
		m_InfoServer.Port="5060";	
		m_InfoServer.UserName="456";
		m_InfoServer.UserAddress="456";	

		fprintf(NetFile,"5060");	
		fprintf(NetFile,"\n5211");
		fprintf(NetFile,"\n123");
		fprintf(NetFile,"\n123");
		fprintf(NetFile,"\n192.168.9.89");
		fprintf(NetFile,"\n5060");
		fprintf(NetFile,"\n456");
		fprintf(NetFile,"\n456");		
	}
	if (NetFile)
	{
		fclose(NetFile);
	}
	delete []temp;
	GetDlgItem(IDC_STR_LOCAL_IP)->SetWindowText(m_InfoClient.IP);
	GetDlgItem(IDC_STR_LOCAL_PORT)->SetWindowText(m_InfoClient.Port);
	GetDlgItem(IDC_STR_LOCAL_ADD)->SetWindowText(m_InfoClient.UserAddress);
	GetDlgItem(IDC_STR_LOCAL_NAME)->SetWindowText(m_InfoClient.UserName);	
	//client������������ҳ��ʼ��	
	m_NetSet.GetDlgItem(IDC_IP_CLIENT)->SetWindowText(m_InfoClient.IP);
	m_NetSet.GetDlgItem(IDC_EDT_CLIENT_PORT)->SetWindowText(m_InfoClient.Port);
	m_NetSet.GetDlgItem(IDC_EDT_CLIENT_ADD)->SetWindowText(m_InfoClient.UserAddress);
	m_NetSet.GetDlgItem(IDC_EDT_CLIENT_NAME)->SetWindowText(m_InfoClient.UserName);
	m_NetSet.GetDlgItem(IDC_EDT_TCP_PORT)->SetWindowText(TCP_Port);
	GetDlgItem(IDC_STR_REMOTE_IP)->SetWindowText(m_InfoServer.IP);
	GetDlgItem(IDC_STR_REMOTE_PORT)->SetWindowText(m_InfoServer.Port);
	GetDlgItem(IDC_STR_REMOTE_ADD)->SetWindowText(m_InfoServer.UserAddress);
	GetDlgItem(IDC_STR_REMOTE_NAME)->SetWindowText(m_InfoServer.UserName);	
	//server������������ҳ��ʼ��	
	m_NetSet.GetDlgItem(IDC_IP_SERVER)->SetWindowText(m_InfoServer.IP);
	m_NetSet.GetDlgItem(IDC_EDT_SERVER_PORT)->SetWindowText(m_InfoServer.Port);
	m_NetSet.GetDlgItem(IDC_EDT_SERVER_ADD)->SetWindowText(m_InfoServer.UserAddress);
	m_NetSet.GetDlgItem(IDC_EDT_SERVER_NAME)->SetWindowText(m_InfoServer.UserName);

	m_Invite.GetDlgItem(IDC_OPERATE)->SetWindowText("DEL");
	m_Invite.GetDlgItem(IDC_STATUS)->SetWindowText("1");
	m_Invite.GetDlgItem(IDC_PRIVILEGE)->SetWindowText("20");

	bNetSet=TRUE;
}

void CUACDlg::InitAlarm()
{
	m_Alarm.GetDlgItem(IDC_EDIT_ADDRESS)->SetWindowText("011061430001");
	m_Alarm.GetDlgItem(IDC_EDIT_PRIVILEGE)->SetWindowText("20");
	m_Alarm.GetDlgItem(IDC_EDIT_LEVEL)->SetWindowText("1");
	m_Alarm.m_AlarmTypeSel.SetCurSel(0);
	m_Alarm.GetDlgItem(IDC_ALARMTYPENUM)->SetWindowText("1");//��ʾ���±���
	m_Alarm.GetDlgItem(IDC_EDIT_ACCEPTIP)->SetWindowText("192.168.1.7");
	m_Alarm.GetDlgItem(IDC_EDIT_ACCEPTPORT)->SetWindowText("5060");
}

void CUACDlg::InitEnableWindow()
{
	//��ʼ��������־���̺Ͳ��Ա��水ť
	EnableWindow(IDC_BTN_LOG,FALSE);
	EnableWindow(IDC_BTN_RESULT,FALSE);
	//������������
	m_NetSet.GetDlgItem(IDC_IP_CLIENT)->EnableWindow(FALSE);
	m_NetSet.GetDlgItem(IDC_EDT_TCP_PORT)->EnableWindow(FALSE);
	m_NetSet.GetDlgItem(IDC_EDT_CLIENT_PORT)->EnableWindow(FALSE);
	m_NetSet.GetDlgItem(IDC_EDT_CLIENT_ADD)->EnableWindow(FALSE);
	m_NetSet.GetDlgItem(IDC_EDT_CLIENT_NAME)->EnableWindow(FALSE);
	//�������������
	m_NetSet.GetDlgItem(IDC_IP_SERVER)->EnableWindow(FALSE);
	m_NetSet.GetDlgItem(IDC_EDT_SERVER_PORT)->EnableWindow(FALSE);
	m_NetSet.GetDlgItem(IDC_EDT_SERVER_ADD)->EnableWindow(FALSE);
	m_NetSet.GetDlgItem(IDC_EDT_SERVER_NAME)->EnableWindow(FALSE);
	m_Alarm.GetDlgItem(IDC_BTN_ALARM_NOTIFY)->EnableWindow(FALSE); 
	m_Alarm.GetDlgItem(IDC_BTN_ALARM_CANCEL)->EnableWindow(FALSE); 
	m_Invite.GetDlgItem(IDC_BTN_BYE)->EnableWindow(FALSE);	
	m_PSTVSetTime.GetDlgItem(IDC_BUTTON_PSTVTIME)->EnableWindow(FALSE);
}

void CUACDlg::OnBnClickedBtnSendClear()
{
	m_ShowSendMsg.SetWindowText("");//IDC_EDT_SENDMSG
}

void CUACDlg::OnBnClickedBtnRecvClear()
{
	m_ShowRecvMsg.SetWindowText("");
}

int CUACDlg::InitSocket(int port)
{
	m_socket=socket(AF_INET,SOCK_DGRAM,0);
	if(INVALID_SOCKET==m_socket)
	{		
		MessageBox("load socket is error","UAC Error",MB_OK|MB_ICONERROR);
		return -1;
	}
	SOCKADDR_IN  addrSocket;
	addrSocket.sin_family=AF_INET;
	addrSocket.sin_port=htons(port);
	addrSocket.sin_addr.S_un.S_addr=htonl(INADDR_ANY);
	int revel;
	revel=bind(m_socket,(SOCKADDR*)&addrSocket,sizeof(SOCKADDR));
	if(SOCKET_ERROR==revel)
	{
		closesocket(m_socket);		
		MessageBox("�˿��ѱ�ռ��","UAC ��ʾ",MB_OK|MB_ICONINFORMATION);
		return -1;
	}	
	return 0;//��ʼ��socket�ɹ�
}

void CUACDlg::SendData(char* data)
{	
	int nServerPort=atoi(m_InfoServer.Port);
	DWORD DWIP;
	DWIP=ntohl(inet_addr(m_InfoServer.IP));
	SOCKADDR_IN  addrto;
	addrto.sin_family=AF_INET;
	addrto.sin_port=htons(nServerPort);
	addrto.sin_addr.S_un.S_addr=htonl(DWIP);
	if (data!=NULL)
	{
		sendto(m_socket,data,strlen(data)+1,0,(SOCKADDR*)&addrto,sizeof(SOCKADDR));	
		string st=data;
		int index=st.find("KeepAlive");
		BOOL b=IsDlgButtonChecked(IDC_CHECK1);
		if (index==string::npos || b )
		{
			ShowSendData(data);
		}
	}	
}
/**
��Ϣ����ʾ
**/
void CUACDlg::ShowSendData(CString StrSendData)
{
	CTime   theTime=CTime::GetCurrentTime(); 
	CString str=theTime.Format(_T("%H:%M:%S"));	
	CString strtemp;
	GetDlgItemText(IDC_EDT_SENDMSG,strtemp);
	strtemp+="\tϵͳʱ�䣺"+str+"\r\n";
	strtemp+=StrSendData;
	strtemp+="\r\n";
	uac_msg_log<<StrSendData<<endl<<endl<<endl;
	SetDlgItemText(IDC_EDT_SENDMSG,strtemp);
	GetDlgItem(IDC_EDT_SENDMSG)->SendMessage(WM_VSCROLL,SB_BOTTOM,0);
}

void CUACDlg::ShowRecvData(CString strRecvData)
{
	CTime   theTime=CTime::GetCurrentTime(); 
	CString str=theTime.Format(_T("%H:%M:%S"));	
	CString strtemp;
	GetDlgItemText(IDC_EDT_RECVMSG,strtemp);
	strtemp+="\tϵͳʱ�䣺"+str+"\r\n";
	strtemp+=strRecvData;
	strtemp+="\r\n";
	uac_msg_log<<strRecvData<<endl<<endl<<endl;
	SetDlgItemText(IDC_EDT_RECVMSG,strtemp);
	GetDlgItem(IDC_EDT_RECVMSG)->SendMessage(WM_VSCROLL,SB_BOTTOM,0);
}

DWORD WINAPI RecvMsg(LPVOID lpParameter)
{
	SOCKET sock=((RECVPARAM*)lpParameter)->sock;
	HWND   hwnd=((RECVPARAM*)lpParameter)->hwnd;
	SOCKADDR_IN addrFrom;
	int len=sizeof(SOCKADDR);
	char RecvBuf[MAXBUFSIZE];	
	memset(RecvBuf,0,MAXBUFSIZE);
	int retvel;
	while(TRUE)
	{
		retvel=recvfrom(sock,RecvBuf,MAXBUFSIZE,0,(SOCKADDR*)&addrFrom,&len);
		if(SOCKET_ERROR==retvel)
			break;
		sprintf(m_SendIP,inet_ntoa(addrFrom.sin_addr));
		if (strcmp(m_SendIP,ProcessIP))
		{
			memset(RecvBuf,0,MAXBUFSIZE);
			continue;
		}
		
		UA_Msg uac_recvtemp;
		strcpy(uac_recvtemp.data,RecvBuf);

		//��ʼ�̼߳����ݵİ�ȫ����
		EnterCriticalSection(&g_uac);
		uac_recvqueue.push(uac_recvtemp);
		LeaveCriticalSection(&g_uac);

		memset(RecvBuf,0,MAXBUFSIZE);
	}
	return 0;
}

DWORD WINAPI DispatchRecvMsg( LPVOID lpParameter )
{	
	while (TRUE)
	{	
		if (uac_recvqueue.empty()==TRUE)
		{
			Sleep(10);
		}
		else
		{

			EnterCriticalSection(&g_uac);
			uac_curqueue=uac_recvqueue.front();
			uac_recvqueue.pop();					
			LeaveCriticalSection(&g_uac);

			Sleep(100);
			char RecvBuf[MAXBUFSIZE];	
			memset(RecvBuf,0,MAXBUFSIZE);
			strcpy(RecvBuf,uac_curqueue.data);
			HWND   hMainWnd=::FindWindow(NULL, _T("UAC"));
			::PostMessage(hMainWnd,WM_RECVDATA,0,(LPARAM)RecvBuf);
		}				
	}
	return 0;
}

DWORD WINAPI SendMsg(LPVOID)
{
	while (TRUE)
	{			
		if (uac_sendqueue.empty()==TRUE)
		{
			Sleep(10);
		}
		else
		{			
			EnterCriticalSection(&g_uac);
			uac_curSendMsg=uac_sendqueue.front();
			uac_sendqueue.pop();			
			LeaveCriticalSection(&g_uac);
			Sleep(100);
			char SendBuf[MAXBUFSIZE];	
			memset(SendBuf,0,MAXBUFSIZE);
			strcpy(SendBuf,uac_curSendMsg.data);			
			HWND   hnd=::FindWindow(NULL, _T("UAC"));		
			::PostMessage(hnd,WM_SENDDATA,0,(LPARAM)SendBuf);
		}				
	}
	return 0;
}

LRESULT CUACDlg::SendMsgData(WPARAM wParm, LPARAM lParam)
{	
	EnterCriticalSection(&g_uac);
	SendData((char *) lParam);
	LeaveCriticalSection(&g_uac);
	return NULL;
}

LRESULT CUACDlg::RecvData(WPARAM wParm, LPARAM lParam)
{
	USES_CONVERSION; 	
	CString str = "";
	str = A2T((char*)lParam);
	CSipMsgProcess *sip;
	sip=new CSipMsgProcess;	
	int len=str.GetLength();	
	int nflag=sip->SipParser((char*)lParam,len);
	switch ( nflag )
	{
	case 0:
		{
			string strTemp = str;
			int index = strTemp.find("KeepAlive");
			if (index == string::npos)//δ�ҵ���KeepALive���ַ��������Ǳ�����Ϣ���ͳɹ��ķ�����Ϣ
			{
				ShowRecvData(str);
			}
			else if (m_bIsShowKeepAliveMsg)//��ʾ������Ϣѡ���ѡ����ʾ����ɹ�����Ϣ
			{
				ShowRecvData("\t\t-----ƽ̨������-----\r\n");
				ShowRecvData(str);
			}
			str.ReleaseBuffer();
		}
		break;
	case 1:
		{
			ShowRecvData(str);
			str.ReleaseBuffer();				
			MessageBox("���Ľ�������","UAC ����",MB_OK|MB_ICONERROR);
		}
		break;
	default:
		break;
	}	
	return NULL;
}

void CUACDlg::OnBnClickedBtnSipRegister()
{
	// TODO: Add your control notification handler code here	
	if (bNetSet)
	{
		int n=atoi(m_InfoClient.Port);
		int nflag=-1;
		nflag=InitSocket(n);
		if ( nflag!=0 )
		{
			return;
		}
		/*FILE *TestIP=NULL;
		TestIP=fopen("UAC����IP��ַ.txt","r");	
		char *temp=new char[40];
		int i=0;
		if (TestIP!=NULL)
		{
			while (1)
			{
				if(feof(TestIP))
					break;
				fscanf(TestIP,"%s\n",temp);
				strcpy(ProcessIP,temp);				
				i++;			
			}
		} 
		else
		{
			TestIP=fopen("UAC����IP��ַ.txt","w");			
			fprintf(TestIP,"192.168.1.16");	
			strcpy(ProcessIP,"192.168.1.16");
		}	
		if (TestIP)
		{
			fclose(TestIP);
		}
		delete []temp;*/
		CString cstrUser,cstrPassword;
		GetDlgItemText(IDC_USERNAMEC,cstrUser);
		GetDlgItemText(IDC_PASSWORDC,cstrPassword);

		GetDlgItem(IDC_USERNAMEC)->EnableWindow(FALSE);
		GetDlgItem(IDC_PASSWORDC)->EnableWindow(FALSE);

		g_authInfo.username=cstrUser;
		g_authInfo.password=cstrPassword;
		g_authInfo.uri="sip:"+m_InfoServer.IP+":"+m_InfoServer.Port;
		RECVPARAM *pRecvParam=new RECVPARAM;
		pRecvParam->sock=m_socket;
		pRecvParam->hwnd=m_hWnd;
		InitializeCriticalSection(&g_uac);///////
		//�����������߳�
		h_UAC_Recv=CreateThread(NULL,0,RecvMsg,(LPVOID)pRecvParam,0,NULL);
		h_UAC_Dispatch=CreateThread(NULL,0,DispatchRecvMsg,NULL,0,NULL);
		h_UAC_Send=CreateThread(NULL,0,SendMsg,NULL,0,NULL);		
		ShowSendData("\t----UDP communication is listening----\r\n");

		//open TCP socket
		int nTCP_Port=atoi(TCP_Port);
		if ( !m_TCPSocket.Create(nTCP_Port) )
			return;
		if( !m_TCPSocket.Listen())
			return;	
		ShowSendData("*************** TCP communication is listening ****************\r\n");

		//SIP Register ���򱣻���
		{
			char *data=new char[MAXBUFSIZE];
			memset(data,0,MAXBUFSIZE);
			CSipMsgProcess *sip;
			sip=new CSipMsgProcess;
			sip->SipRegisterCreate(&data,m_InfoServer,m_InfoClient);
			//����Ȩǩ
			//sip->SipRegisterWithAuthCreate(&data,m_InfoServer,m_InfoClient);
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,data);

			//SIP�Ự�İ�ȫ����
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);

			delete data;		
			ShowTestLogTitle="Register Test";
			ShowTestLogData+="REGISTER ------->  \r\n";
		}

		//����SIP��ť������
		EnableWindow(IDC_BTN_SIP_REGISTER,FALSE);//ע�ᰴť������
		m_NetSet.m_kAlterBtn.EnableWindow(FALSE);
		EnableWindow(IDC_BTN_LOG,TRUE);
		SetTimer(3,5000,NULL);
	} 
	else
	{
		MessageBox("��ȷ����������","UAC ��ʾ",MB_OK|MB_ICONINFORMATION);
	}
}

void CUACDlg::OnBnClickedBtnSet()
{
	CSetTestMember dlg;
	dlg.DoModal();
}

void CUACDlg::OnBnClickedBtnLog()
{
	CLOG dlg;
	dlg.DoModal();
}

void CUACDlg::OnTimer(UINT_PTR nIDEvent)
{
	if ( 0/*bRtspLive*/ )
	{
		nRstpTimeCount++;
		if ( nRstpTimeCount==2 )
		{
			nRstpTimeCount=0;
			if ( bRtspLiveFlag )
			{
				bRtspLiveFlag=FALSE;
			}
			else
			{
				ShowRecvData("---------��ʷͼ��������ʱ----------\r\n");
			}		
		}
	}	
	if ( 0/*bACK*/ )
	{
		nRealTimeCount++;
		if ( nRealTimeCount==2 )
		{
			nRealTimeCount=0;
			if ( bRealTimeFlag)
			{
				bRealTimeFlag=FALSE;
			}
			else
			{
				ShowRecvData("---------ʵʱ��������ʱ----------\r\n");
			}		
		}		
	}
	if( nIDEvent == 1) //ע��ɹ���ƽ̨���м��6�����ҵ�������Ϣ����
	{
		if (bKeepAlive)//ע��ɹ��󱣻��־λ��
		{
			//nKeepTimeCount++;
			//if ( nKeepTimeCount==5)
			//{
			//	nKeepTimeCount=0;
				char *data=new char[MAXBUFSIZE];
				memset(data,0,MAXBUFSIZE);
				CSipMsgProcess *sip;
				sip=new CSipMsgProcess;
				string xml="<?xml version=\"1.0\"?>\r\n";
				xml+="<Action>\r\n";
				xml+="<Notify>\r\n";
				xml+="<Variable>KeepAlive</Variable>\r\n";
				xml+="</Notify>\r\n";
				xml+="</Action>\r\n";	
				char *strxml=new char[XMLSIZE];
				strcpy(strxml,xml.c_str());
				sip->DOKeepAliveMsg(&data,m_InfoServer,m_InfoClient,strxml);
				UA_Msg uac_sendtemp;

				strcpy(uac_sendtemp.data,data);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);

				/*if (!bSipRegister)
				{
					ShowSendData(data);
				}	*/
				delete strxml;
				delete data;
			//}		
		}
	}	
	CDialog::OnTimer(nIDEvent);
}

void CUACDlg::OnBnClickedCancel()
{
	// TODO: Add your control notification handler code here
	if (IDYES == MessageBox("ȷ���˳���",NULL,MB_YESNO|MB_ICONINFORMATION))
	{
		if (INVALID_SOCKET!=m_socket)
		{
			closesocket(m_socket);
		}
		KillTimer(3);	
		CloseHandle(h_UAC_Send);
		CloseHandle(h_UAC_Dispatch);
		CloseHandle(h_UAC_Recv);
		OnCancel();
	}	
}

int CUACDlg::AnalyseMsg(char* msg)
{
	string strTemp(msg);		
	string temp;	
	string sessiontemp;
	string setupTemp;
	string dest;	
	string::size_type VariableStart;
	string::size_type VariableEnd;	
	if ( (VariableStart=strTemp.find("OPTIONS",0)) !=string::npos )
	{
		dest="RTSP/1.0 200 OK\r\n";		
		if( (VariableStart=strTemp.find("CSeq:",0)) !=string::npos )
		{				
			if( (VariableEnd=strTemp.find("\r\n",VariableStart)) !=string::npos )
			{				
				temp=strTemp.substr(VariableStart,VariableEnd-VariableStart);
				dest+=temp;
				dest+="\r\n";
			}
		}
		if ( (VariableStart=strTemp.find("Session:",0)) !=string::npos)
		{
			if( (VariableEnd=strTemp.find("\r\n",VariableStart)) !=string::npos )
			{				
				sessiontemp=strTemp.substr(VariableStart,VariableEnd-VariableStart);
				dest+=sessiontemp;
				dest+="\r\n";
			}
		}				
		dest+="Public: DESCRIBE, SETUP, TEARDOWN, PLAY, OPTIONS\r\n\r\n";
		SendTCPMsg(dest.c_str());		
		if ( !brtspKeeplive )
		{
			//ShowSendData(dest.c_str());			
			brtspKeeplive=TRUE;
			bRtspLive=TRUE;
			if ( (VariableStart=strTemp.find("Session:",0)) !=string::npos)
			{
				if( (VariableEnd=strTemp.find("\r\n",VariableStart)) !=string::npos )
				{				
					Session=strTemp.substr(VariableStart,VariableEnd-VariableStart);	
					bRtspLiveFlag=TRUE;
				}
			}
		}
		else
		{
			bRtspLiveFlag=TRUE;
			temp.erase(0,temp.length());					
			return 0;
		}
		temp.erase(0,temp.length());		
	}
	else if ( (VariableStart=strTemp.find("DESCRIBE",0)) !=string::npos )
	{
		dest="RTSP/1.0 200 OK\r\n";
		if( (VariableStart=strTemp.find("CSeq:",0)) !=string::npos )
		{				
			if( (VariableEnd=strTemp.find("\r\n",VariableStart)) !=string::npos )
			{			
				temp=strTemp.substr(VariableStart,VariableEnd-VariableStart);	
				dest+=temp;
				dest+="\r\n";
			}
		}		
		dest+="Date: 20 April 2013 12:00:00 GMT\r\n";
		dest+="Content-Type: application/sdp\r\n";
		dest+="Content-Length: 0\r\n\r\n";
		//dest+="s= H3C Streaming Media\r\n";
		SendTCPMsg(dest.data());
		//ShowSendData(dest.c_str());	
		temp.erase(0,temp.length());
	}
	else if ( (VariableStart=strTemp.find("SETUP",0)) !=string::npos )
	{
		dest="RTSP/1.0 200 OK\r\n";
		if( (VariableStart=strTemp.find("CSeq:",0)) !=string::npos )
		{				
			if( (VariableEnd=strTemp.find("\r\n",VariableStart)) !=string::npos )
			{			
				setupTemp = strTemp.substr(VariableStart,VariableEnd-VariableStart);
				dest += setupTemp;
				dest += "\r\n";
			}
		}
		if ( (VariableStart=strTemp.find("Transport:",0)) !=string::npos )
		{
			if ( (VariableEnd=strTemp.find("\r\n",VariableStart)) !=string::npos )
			{
				temp=strTemp.substr(VariableStart,VariableEnd-VariableStart);
			}
			dest+=Session;	
			dest+="\r\n";
			dest+=temp;	
			dest+="\r\n";
			dest+="ssrc=1AF9BD;source=172.18.19.122;server_port=7000-7001\r\n\r\n";
			SendTCPMsg(dest.c_str());
			//ShowSendData(dest.c_str());
			temp.erase(0,temp.length());
		}
		else 
		{
			return 1;
		}		
	}
	else if ( (VariableStart=strTemp.find("PLAY",0)) !=string::npos )
	{
		dest="RTSP/1.0 200 OK\r\n";
		if ( (VariableStart=strTemp.find("CSeq:",0)) !=string::npos )
		{
			if ( (VariableEnd=strTemp.find("\r\n",VariableStart)) !=string::npos )
			{
				temp=strTemp.substr(VariableStart,VariableEnd-VariableStart);
				dest+=temp;	
				dest+="\r\n";
			}		
		}
		if ( (VariableStart=strTemp.find("Session:",0)) !=string::npos )
		{
			if ( (VariableEnd=strTemp.find("\r\n",VariableStart)) !=string::npos )
			{
				temp=strTemp.substr(VariableStart,VariableEnd-VariableStart);
				dest+=temp;	
				dest+="\r\n";
			}		
		}
		if ( (VariableStart=strTemp.find("Range:",0)) !=string::npos )
		{
			if ( (VariableEnd=strTemp.find("\r\n",VariableStart)) !=string::npos )
			{
				temp=strTemp.substr(VariableStart,VariableEnd-VariableStart);
				dest+=temp;	
				dest+="\r\n";
			}		
		}
		if ( (VariableStart=strTemp.find("Scale:",0)) !=string::npos )
		{
			if ( (VariableEnd=strTemp.find("\r\n",VariableStart)) !=string::npos )
			{
				temp=strTemp.substr(VariableStart,VariableEnd-VariableStart);
				dest+=temp;	
				dest+="\r\n";
			}		
		}
		dest+="\r\n";
		SendTCPMsg(dest.c_str());
		//ShowSendData(dest.c_str());
		temp.erase(0,temp.length());		
	}
	else if ( (VariableStart=strTemp.find("TEARDOWN",0)) !=string::npos )
	{
		dest="RTSP/1.0 200 OK\r\n";
		if ( (VariableStart=strTemp.find("CSeq:",0)) !=string::npos )
		{
			if ( (VariableEnd=strTemp.find("\r\n",VariableStart)) !=string::npos )
			{
				temp=strTemp.substr(VariableStart,VariableEnd-VariableStart);
				dest+=temp;	
				dest+="\r\n";
			}		
		}
		if ( (VariableStart=strTemp.find("Session:",0)) !=string::npos )
		{
			if ( (VariableEnd=strTemp.find("\r\n",VariableStart)) !=string::npos )
			{
				temp=strTemp.substr(VariableStart,VariableEnd-VariableStart);
				dest+=temp;	
				dest+="\r\n";
			}		
		}
		dest+="\r\n";
		SendTCPMsg(dest.c_str());
		//ShowSendData(dest.c_str());
		temp.erase(0,temp.length());
		brtspKeeplive=FALSE;
		bRtspLive=FALSE;			
	}
	else
	{
		return 1;
	}	
	return 0;
}

LRESULT CUACDlg::OnReceive(WPARAM wParam, LPARAM lParam)
{		
	CMySocket *p_curClient = (CMySocket*)wParam;
	char buf[MAXBUFSIZE];
	memset(buf,0,MAXBUFSIZE);
	p_curClient->Receive(buf,MAXBUFSIZE);
	Sleep(100);
	int nflag=1;
	nflag = AnalyseMsg(buf);
	switch ( nflag )
	{
	case 0:
		{			
			ShowRecvData(buf);			
		}
		break;
	case 1:
		{
			AfxMessageBox("������Ϣ��������",MB_OK|MB_ICONERROR);						
			ShowRecvData(buf);			
		}
		break;
	default:
		break;
	}		
	return NULL;
}

LRESULT CUACDlg::OnClientClose(WPARAM wParam, LPARAM lParam)
{
	CMySocket *p_delClient = (CMySocket*)wParam;
	//close member
	p_delClient->ShutDown();
	char buffer[MAXBUFSIZE];
	while(p_delClient->Receive(buffer, MAXBUFSIZE)>0)
	{
	}
	p_delClient->Close();	
	POSITION psCur, psList = m_lsClient.GetHeadPosition();
	CMySocket *p_curClient;
	while(psList!=NULL)
	{
		psCur = psList;
		p_curClient = (CMySocket *)m_lsClient.GetNext(psList);
		if(p_delClient==p_curClient)
		{
			m_lsClient.RemoveAt(psCur);
			break;
		}
	}
	delete p_delClient;
	return NULL;
}

void CUACDlg::SendTCPMsg(const char *Msg)
{
	CMySocket *m_pClient;
	POSITION psList = m_lsClient.GetHeadPosition();
	while(psList!=NULL)
	{
		m_pClient = (CMySocket *)m_lsClient.GetNext(psList);
		m_pClient->SendMsg(Msg);
		ShowSendData(Msg);
	}
}

LRESULT CUACDlg::OnAccept(WPARAM wparam, LPARAM lparam)
{
	CMySocket *pNewClient = new CMySocket;
	pNewClient->Initialize(this);
	m_TCPSocket.Accept(*pNewClient);	
	m_lsClient.AddTail(pNewClient);

	return NULL;
}

void CUACDlg::OnCbnSelchangeBoxTestmember()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	int nCurSel=m_TestMember.GetCurSel();
	strcpy(ProcessIP,ProductTestMember[nCurSel].IP);
}

void CUACDlg::OnStnClickedSabout()
{
	CAboutDlg dlg;
	dlg.DoModal();
}

void CUACDlg::OnCbnSelchangeCombo1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString selIpStr;
	m_IpGroup.GetWindowTextA(selIpStr);
	GetDlgItem(IDC_STR_LOCAL_IP)->SetWindowTextA(selIpStr);
	m_InfoClient.IP = selIpStr;
}

void CUACDlg::OnBnClickedButtonReboot()
{
	char strPath[100];
	GetModuleFileName(NULL, strPath, 100);

	//�����ػ����̣��������½��̳ɹ�����WM_QUIT��Ϣ����ԭ���Ľ��̣�
	STARTUPINFO startInfo;
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&startInfo, sizeof(STARTUPINFO));
	startInfo.cb = sizeof(STARTUPINFO);
	if (CreateProcess(NULL, (LPTSTR)(LPCTSTR)strPath, NULL, NULL, FALSE, 0, NULL, NULL, &startInfo, &processInfo))
	{
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
		PostQuitMessage(WM_CLOSE);
	}
}

void CUACDlg::OnBnClickedCheck1()
{
	m_bIsShowKeepAliveMsg = IsDlgButtonChecked(IDC_CHECK1);
}
