#pragma once
#include "afxwin.h"


// CNetSet dialog

class CNetSet : public CDialog
{
	DECLARE_DYNAMIC(CNetSet)

public:
	CNetSet(CWnd* pParent = NULL);   // standard constructor
	virtual ~CNetSet();

// Dialog Data
	enum { IDD = IDD_DLG_NETSET };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	// �޸İ�ť�ؼ�����
	CButton m_kAlterBtn;
	afx_msg void OnBnClickedBtnOk();
};
