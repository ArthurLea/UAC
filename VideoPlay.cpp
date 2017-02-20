// VideoPlay.cpp : implementation file
//

#include "stdafx.h"
#include "UAC.h"
#include "VideoPlay.h"


// CVideoPlay dialog

IMPLEMENT_DYNAMIC(CVideoPlay, CDialog)

CVideoPlay::CVideoPlay(CWnd* pParent /*=NULL*/)
	: CDialog(CVideoPlay::IDD, pParent)
{

}

CVideoPlay::~CVideoPlay()
{
}

void CVideoPlay::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CVideoPlay, CDialog)
END_MESSAGE_MAP()


// CVideoPlay message handlers
