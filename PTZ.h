#pragma once


// CPTZ dialog

class CPTZ : public CDialog
{
	DECLARE_DYNAMIC(CPTZ)

public:
	CPTZ(CWnd* pParent = NULL);   // standard constructor
	virtual ~CPTZ();

// Dialog Data
	enum { IDD = IDD_DLG_PTZ };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
};
