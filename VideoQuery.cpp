// VideoQuery.cpp : implementation file
//

#include "stdafx.h"
#include "UAC.h"
#include "VideoQuery.h"


// CVideoQuery dialog

IMPLEMENT_DYNAMIC(CVideoQuery, CDialog)

CVideoQuery::CVideoQuery(CWnd* pParent /*=NULL*/)
	: CDialog(CVideoQuery::IDD, pParent)
{

}

CVideoQuery::~CVideoQuery()
{
}

void CVideoQuery::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CVideoQuery, CDialog)
END_MESSAGE_MAP()


// CVideoQuery message handlers
