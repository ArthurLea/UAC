#pragma once
#include "afxwin.h"


// CLOG dialog

class CLOG : public CDialog
{
	DECLARE_DYNAMIC(CLOG)

public:
	CLOG(CWnd* pParent = NULL);   // standard constructor
	virtual ~CLOG();

// Dialog Data
	enum { IDD = IDD_DLG_LOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedBtnRefresh();
	virtual BOOL OnInitDialog();
	// …Ë÷√Ωπµ„
	CButton m_focus;
};
