#ifndef DXP_H
#define DXP_H
#include "stdafx.h"
#include <queue>
#include <vector>
using namespace std;
#define MAXBUFSIZE 4000
#define SIPSIZE 1000
#define  XMLSIZE 3000
#define  NUMSIZE 10
#define  HOSTSIZE 30


struct RECVPARAM
{
	SOCKET sock;
	HWND hwnd;
};
//事件类型
enum{Register,NodeType,Invite,CANCEL,PTZ,PreBitSet,HistoryQuery,CatalogQuery,DeviceInfQuery,FlowQuery,HistoryPlay,EncoderSet,Alarm,TimeSet,TimeGet};
//服务端的信息
struct InfoServer
{
	CString UserName;
	CString UserAddress;
	CString IP;
	CString Port;
};
struct Authenticate
{
	string realm;
	string nonce;
	string opaque;
	string qop;

	string username;
	string uri;
	string response;
	string cnonce;
	string nc;
	string password;
};
//客户端的信息
struct InfoClient
{
	CString UserName;
	CString UserAddress;
	CString IP;
	CString Port;
};
struct ProductMember
{
	char IP[HOSTSIZE];
};
struct CallID
{
	char Host[HOSTSIZE];
	char Num[NUMSIZE];
	char Tag[NUMSIZE];
};
struct sCallID
{
	char CurHost[HOSTSIZE];
	char CurNum[NUMSIZE];
	char CurTag[NUMSIZE];
	int    nSataus;
};
struct InfoAlarm
{
	string UserCode;
	string Level;
	string AlarmType;
	string Address;
	string AcceptIP;
	string AcceptPort;
	string CallID;
};
struct UA_Msg
{
	//网络收包或发包数据缓冲区
	char data[MAXBUFSIZE];
};
DWORD WINAPI DispatchRecvMsg( LPVOID );
DWORD WINAPI RecvMsg(LPVOID lpParameter);
DWORD WINAPI SendMsg(LPVOID);

#endif