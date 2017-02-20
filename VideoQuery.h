#pragma once


// CVideoQuery dialog

class CVideoQuery : public CDialog
{
	DECLARE_DYNAMIC(CVideoQuery)

public:
	CVideoQuery(CWnd* pParent = NULL);   // standard constructor
	virtual ~CVideoQuery();

// Dialog Data
	enum { IDD = IDD_DLG_VIDEOQUERY };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
};
