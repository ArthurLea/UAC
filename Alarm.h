#pragma once
#include "afxwin.h"
#include <vector>
// CAlarm dialog
using namespace std;
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
	vector<CString> arrAlarmType;
	afx_msg void OnBnClickedBtnAlarmCancel();
	afx_msg void OnBnClickedBtnAlarmNotify3();
	virtual BOOL OnInitDialog();
	CComboBox m_selAddress;
	CComboBox m_AlarmTypeSel;
	vector<CString> address;
	afx_msg void OnCbnSelchangeComboAlarmtypename();
};
