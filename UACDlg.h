// UACDlg.h : ͷ�ļ�
//
#pragma once
#include "NetSet.h"
#include "Alarm.h"
#include "CoderSet.h"
#include "Invite.h"
#include "PTZ.h"
#include "VideoQuery.h"
#include "VideoPlay.h"
#include "afxcmn.h"
#include "afxwin.h"
#include "DXP.h"
#include "SetTestMember.h"
#include "LOG.h"
#include "SipMsgProcess.h"
#include "MySocket.h"
#include "PSTVSetTime.h"
//�Զ�����Ϣ
#define WM_RECVDATA    (WM_USER+115)
#define  WM_SENDDATA  (WM_USER+116)
// CUACDlg �Ի���
class CUACDlg : public CDialog
{
// ����
public:
	CUACDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_UAC_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	void InitProgram();
	void InitNetSet();
	void InitAlarm();
	void InitEnableWindow();
	int InitSocket(int port);
	void ShowSendData(CString StrSendData);
	void ShowRecvData(CString strRecvData);
	BOOL EnableWindow(UINT uID, BOOL bEnable);
	int GetLocalHostName(CString &sHostName);
	int GetLocalIp(const CString &sHostName, CString &sIpAddress);	
	LRESULT RecvData(WPARAM wParm, LPARAM lParam);
	LRESULT SendMsgData(WPARAM wParm, LPARAM lParam);
	void SendData(char *data);
	/////////////TCP communication
	LRESULT OnAccept(WPARAM wparam=NULL, LPARAM lparam=NULL);	
	LRESULT OnReceive(WPARAM wParam, LPARAM lParam);
	LRESULT OnClientClose(WPARAM wParam, LPARAM lParam);	
	void SendTCPMsg(const char *Msg);
	int AnalyseMsg(char* msg);
	CMySocket m_TCPSocket;
	CPtrList m_lsClient;
	string Session;
	BOOL brtspKeeplive;
	BOOL bRtspLive;
	BOOL bRtspLiveFlag;	
	int nRstpTimeCount;
	int nKeepCseq;

public:
	vector <ProductMember> ProductTestMember;
	InfoServer m_InfoServer;
	InfoClient m_InfoClient;	
	vector<InfoAlarm> m_InfoAlarm;
	BOOL balarmsubscribe;

	char alarmToTag[50];
	char alarmFromTag[50];

	char invite100tag[50];
	char *contact;
	char *byestring;
	BOOL bSipRegister;
	BOOL bNodeType;
	BOOL bKeepAlive;
	BOOL bACK;
	BOOL bBYE;
	BOOL bShowRealTime;
	BOOL bRealTimeFlag;
	int nRealTimeCount;
	int nKeepTimeCount;

	//�¼���CallID
	/*modified by Bsp Lee*/
	vector<string> AlarmCallID;//UAC�˶�UAS���¼�Ԥ��CallID�Ĵ洢
	CallID RegisterCallID;
	CallID KeepAliveID;
	CallID TimeSetID;
	CallID NodeTypeCallID;	
	sCallID CurStatusID;
	CString ShowTestLogTitle;
	CString ShowTestLogData;
public:
	//��Ա����
	SOCKET m_socket;
	BOOL bNetSet;
	// ��ǩҳ
	CTabCtrl m_Ctab;
	CNetSet m_NetSet;
	CInvite m_Invite;
	CPTZ m_PTZ;
	CVideoQuery m_VideoQuery;
	CVideoPlay m_VideoPlay;
	CCoderSet m_CoderSet;
	CAlarm m_Alarm;
	CPSTVSetTime m_PSTVSetTime;
	// �����б���ʾ
	CComboBox m_TestMember;
	afx_msg void OnTcnSelchangeTab(NMHDR *pNMHDR, LRESULT *pResult);
	// ��ʾ������Ϣ
	CEdit m_ShowSendMsg;
	// ��ʾ������Ϣ
	CEdit m_ShowRecvMsg;
	afx_msg void OnBnClickedBtnSendClear();
	afx_msg void OnBnClickedBtnRecvClear();
	afx_msg void OnBnClickedBtnSipRegister();
	afx_msg void OnBnClickedBtnSet();
	afx_msg void OnBnClickedBtnLog();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnBnClickedCancel();
public:
	CString TCP_Port;
	afx_msg void OnCbnSelchangeBoxTestmember();
	afx_msg void OnStnClickedSabout();
	CComboBox m_IpGroup;
	afx_msg void OnCbnSelchangeCombo1();
	afx_msg void OnBnClickedButtonReboot();
	afx_msg void OnBnClickedCheck1();
	BOOL m_bIsShowKeepAliveMsg;
};
