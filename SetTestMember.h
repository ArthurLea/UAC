#pragma once
#include "afxwin.h"


// CSetTestMember dialog

class CSetTestMember : public CDialog
{
	DECLARE_DYNAMIC(CSetTestMember)

public:
	CSetTestMember(CWnd* pParent = NULL);   // standard constructor
	virtual ~CSetTestMember();

// Dialog Data
	enum { IDD = IDD_DLG_TESTMEMBER };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedBtnAdd();
	afx_msg void OnBnClickedBtnAlter();
	afx_msg void OnBnClickedBtnDelete();
	virtual BOOL OnInitDialog();
	// �����б�
	CComboBox m_QueryTestMember;
	// ��ʾ�޸ĵĲ��Գ�������
	//CEdit m_sTestAlter;	
	afx_msg void OnCbnSelchangeBoxList();
};
