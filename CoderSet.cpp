// CoderSet.cpp : implementation file
//

#include "stdafx.h"
#include "UAC.h"
#include "CoderSet.h"


// CCoderSet dialog

IMPLEMENT_DYNAMIC(CCoderSet, CDialog)

CCoderSet::CCoderSet(CWnd* pParent /*=NULL*/)
	: CDialog(CCoderSet::IDD, pParent)
{

}

CCoderSet::~CCoderSet()
{
}

void CCoderSet::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_ENCODERPARAM, m_EncoderParam);
}


BEGIN_MESSAGE_MAP(CCoderSet, CDialog)
END_MESSAGE_MAP()


// CCoderSet message handlers
