// UACDlg.h : 头文件
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
//自定义消息
#define WM_RECVDATA    (WM_USER+115)
#define  WM_SENDDATA  (WM_USER+116)
// CUACDlg 对话框
class CUACDlg : public CDialog
{
// 构造
public:
	CUACDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_UAC_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
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

	//事件的CallID
	/*modified by Bsp Lee*/
	vector<string> AlarmCallID;//UAC端对UAS的事件预警CallID的存储
	CallID RegisterCallID;
	CallID KeepAliveID;
	CallID TimeSetID;
	CallID NodeTypeCallID;	
	sCallID CurStatusID;
	CString ShowTestLogTitle;
	CString ShowTestLogData;
public:
	//成员变量
	SOCKET m_socket;
	BOOL bNetSet;
	// 标签页
	CTabCtrl m_Ctab;
	CNetSet m_NetSet;
	CInvite m_Invite;
	CPTZ m_PTZ;
	CVideoQuery m_VideoQuery;
	CVideoPlay m_VideoPlay;
	CCoderSet m_CoderSet;
	CAlarm m_Alarm;
	CPSTVSetTime m_PSTVSetTime;
	// 厂商列表显示
	CComboBox m_TestMember;
	afx_msg void OnTcnSelchangeTab(NMHDR *pNMHDR, LRESULT *pResult);
	// 显示发送消息
	CEdit m_ShowSendMsg;
	// 显示接收消息
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
