#include "StdAfx.h"
#include "MySocket.h"
#include "DXP.h"

CMySocket::CMySocket(void)
{
}

CMySocket::~CMySocket(void)
{
}

void CMySocket::Initialize(CWnd *_pWnd)
{
	m_pWnd = _pWnd;
}


void CMySocket::OnAccept(int nErrorCode)
{
	if(nErrorCode==0)
	{
		m_pWnd->SendMessage(WM_ACCEPT);
	}

	CAsyncSocket::OnAccept(nErrorCode);
}

void CMySocket::OnReceive(int nErrorCode)
{
	if(nErrorCode==0)
	{
		m_pWnd->SendMessage(WM_RECEIVE, (WPARAM)this);
	}

	CAsyncSocket::OnReceive(nErrorCode);
}

void CMySocket::OnClose(int nErrorCode)
{
	if(nErrorCode==0)
	{
		m_pWnd->SendMessage(WM_CLIENTCLOSE, (WPARAM)this);
	}

	CAsyncSocket::OnClose(nErrorCode);
}

void CMySocket::SendMsg(const char *Msg)
{
	int nLength=strlen(Msg)+1;
	Send(Msg, nLength);
}