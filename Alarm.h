#pragma once


// CAlarm dialog

class CAlarm : public CDialog
{
	DECLARE_DYNAMIC(CAlarm)

public:
	CAlarm(CWnd* pParent = NULL);   // standard constructor
	virtual ~CAlarm();

// Dialog Data
	enum { IDD = IDD_DLG_ALARM };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedBtnAlarmNotify();
	afx_msg void OnBnClickedBtnTimeset();
	afx_msg void OnBnClickedBtnAlarmCancel();
	afx_msg void OnBnClickedBtnAlarmNotify3();
};
