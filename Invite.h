#pragma once
#include "afxwin.h"
#include <vector>
using namespace std;

// CInvite dialog

class CInvite : public CDialog
{
	DECLARE_DYNAMIC(CInvite)

public:
	CInvite(CWnd* pParent = NULL);   // standard constructor
	virtual ~CInvite();

// Dialog Data
	enum { IDD = IDD_DLG_INVITE };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedBtnBye();
	afx_msg void OnBnClickedButton1();
	CComboBox m_address;
	vector<CString> address;
};
