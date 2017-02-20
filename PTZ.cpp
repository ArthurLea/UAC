// PTZ.cpp : implementation file
//

#include "stdafx.h"
#include "UAC.h"
#include "PTZ.h"


// CPTZ dialog

IMPLEMENT_DYNAMIC(CPTZ, CDialog)

CPTZ::CPTZ(CWnd* pParent /*=NULL*/)
	: CDialog(CPTZ::IDD, pParent)
{

}

CPTZ::~CPTZ()
{
}

void CPTZ::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CPTZ, CDialog)
END_MESSAGE_MAP()


// CPTZ message handlers
