#pragma once
#include "afxsock.h"

#define WM_SEND				WM_USER + 100
#define WM_RECEIVE			WM_USER + 101
#define WM_ACCEPT			WM_USER + 102
#define WM_CLIENTCLOSE		WM_USER + 103

class CMySocket :
	public CAsyncSocket
{
public:
	CMySocket(void);
	~CMySocket(void);

public:
	void SendMsg( const char *Msg);

	void Initialize(CWnd *_pWnd);

protected:
	virtual void OnClose(int nErrorCode);
	virtual void OnReceive(int nErrorCode);
	virtual void OnAccept(int nErrorCode);

private:
	CWnd *m_pWnd;

};
