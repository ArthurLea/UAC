#include "StdAfx.h"
#include "SipMsgProcess.h"
#include <math.h>
#include "md5.h"
#include "string.h"
#include "Common.h"
using namespace std;
extern queue<UA_Msg> uac_sendqueue;
extern CRITICAL_SECTION g_uac;
extern vector<CString> HistoryVideoList;
extern vector<CString> PresetInfoList;
extern struct Authenticate g_authInfo;
osip_cseq_t *cseq;
CSipMsgProcess::CSipMsgProcess(void)
{
	parser_init();
	osip_message_init(&m_SipMsg.msg);
	osip_via_init(&m_SipMsg.via);
	osip_to_init(&m_SipMsg.to);
	osip_from_init(&m_SipMsg.from);
	osip_call_id_init(&m_SipMsg.callid);
	osip_contact_init(&m_SipMsg.contact);
	osip_cseq_init(&m_SipMsg.cseq);
	osip_content_type_init(&m_SipMsg.content_type);
	osip_content_length_init(&m_SipMsg.content_length);
	osip_uri_init(&m_SipMsg.uriServer);
	osip_uri_init(&m_SipMsg.uriClient);
	m_Type=56;
}

CSipMsgProcess::~CSipMsgProcess(void)
{
	//OISP资源释放
	osip_via_free(m_SipMsg.via);
	osip_to_free(m_SipMsg.to);
	osip_from_free(m_SipMsg.from);
	osip_call_id_free(m_SipMsg.callid);
	osip_contact_free(m_SipMsg.contact);
	osip_cseq_free(m_SipMsg.cseq);
	osip_content_type_free(m_SipMsg.content_type);
	osip_content_length_free(m_SipMsg.content_length);
	osip_uri_free(m_SipMsg.uriServer);
	osip_uri_free(m_SipMsg.uriClient);
	osip_message_free(m_SipMsg.msg);
}

int CSipMsgProcess::SipRegisterCreate(char **strRegister,InfoServer m_InfoServer,InfoClient m_InfoClient)
{	
	char FromTag[10];
	char CallID[10];
	//远程配置信息
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//本地配置信息
	char *srcCode=(LPSTR)(LPCTSTR)m_InfoClient.UserAddress;
	char *srcUserName=(LPSTR)(LPCTSTR)m_InfoClient.UserName;
	char *srcIP=(LPSTR)(LPCTSTR)m_InfoClient.IP;
	char *srcPort=(LPSTR)(LPCTSTR)m_InfoClient.Port;	
	int RandData;
	srand((unsigned int)time(0));
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(FromTag,str);
	RandData=rand();
	itoa(RandData,str,10);
	strcpy(CallID,str);

	char *dest;
	CSipMsgProcess *SipRegister=new CSipMsgProcess;
	////////////////////////
	osip_uri_set_host(SipRegister->m_SipMsg.uriServer,dstIP);
	osip_uri_set_scheme(SipRegister->m_SipMsg.uriServer,"sip");
	osip_uri_set_username(SipRegister->m_SipMsg.uriServer,dstCode);
	osip_uri_set_port(SipRegister->m_SipMsg.uriServer,dstPort);	

	osip_uri_set_host(SipRegister->m_SipMsg.uriClient,srcIP);
	osip_uri_set_scheme(SipRegister->m_SipMsg.uriClient,"sip");
	osip_uri_set_username(SipRegister->m_SipMsg.uriClient,srcCode);
	osip_uri_set_port(SipRegister->m_SipMsg.uriClient,srcPort);

	osip_via_set_version(SipRegister->m_SipMsg.via,"2.0");
	osip_via_set_protocol(SipRegister->m_SipMsg.via,"UDP");
	osip_via_set_port(SipRegister->m_SipMsg.via,srcPort);
	char branch[20] = "z9hG4bK";
	for (int i = 0; i < 8; i++)
	{
		RandData = rand() % 10;
		branch[i + 7] = RandData + '0';
	}
// 	itoa(RandData,sdtr,16);
	osip_via_set_branch(SipRegister->m_SipMsg.via,branch);//随机数
	osip_via_set_host(SipRegister->m_SipMsg.via,srcIP);

	osip_call_id_set_host(SipRegister->m_SipMsg.callid,srcIP);
	osip_call_id_set_number(SipRegister->m_SipMsg.callid,CallID);//随机数
	//保留本注册的消息的CallID信息
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	strcpy(pWnd->RegisterCallID.Host,srcIP);
	strcpy(pWnd->RegisterCallID.Num,CallID);

	osip_from_set_displayname(SipRegister->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipRegister->m_SipMsg.from,FromTag);//随机数
	osip_from_set_url(SipRegister->m_SipMsg.from,SipRegister->m_SipMsg.uriClient);
	strcpy(pWnd->RegisterCallID.Tag,FromTag);

	osip_to_set_displayname(SipRegister->m_SipMsg.to,srcUserName);	
	osip_to_set_url(SipRegister->m_SipMsg.to,SipRegister->m_SipMsg.uriClient);

	osip_cseq_set_method(SipRegister->m_SipMsg.cseq,"REGISTER");
	osip_cseq_set_number(SipRegister->m_SipMsg.cseq,"1");

	osip_message_set_uri(SipRegister->m_SipMsg.msg,SipRegister->m_SipMsg.uriServer);
	osip_message_set_method(SipRegister->m_SipMsg.msg,"REGISTER");

	osip_contact_set_url(SipRegister->m_SipMsg.contact,SipRegister->m_SipMsg.uriClient);
	//osip_contact_set_displayname(SipRegister->m_SipMsg.contact,srcUserName);
	osip_message_set_expires(SipRegister->m_SipMsg.msg,Common::EXPIRES_VALUE);
	osip_message_set_max_forwards(SipRegister->m_SipMsg.msg,Common::MAX_FORWARD_VALUE);

	//osip_message_set_content_length(SipRegister->m_SipMsg.msg,"0");		

	osip_call_id_to_str(SipRegister->m_SipMsg.callid,&dest);
	osip_message_set_call_id(SipRegister->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_from_to_str(SipRegister->m_SipMsg.from,&dest);
	osip_message_set_from(SipRegister->m_SipMsg.msg,dest);	
	osip_free(dest);

	osip_to_to_str(SipRegister->m_SipMsg.to,&dest);
	osip_message_set_to(SipRegister->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_contact_to_str(SipRegister->m_SipMsg.contact,&dest);
	osip_message_set_contact(SipRegister->m_SipMsg.msg,dest);
	strcpy(pWnd->contact,dest);
	osip_free(dest);

	osip_cseq_to_str(SipRegister->m_SipMsg.cseq,&dest);
	osip_message_set_cseq(SipRegister->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_via_to_str(SipRegister->m_SipMsg.via,&dest);
	//CString cst=dest;
	//cst="Via: "+CString("SIP/2.0/UDP 192.168.34.6:3456")+"\r\n";
	//CString cstr=st.GetBuffer(st.GetLength());
	osip_message_set_via(SipRegister->m_SipMsg.msg,dest);
	//osip_message_set_via(SipRegister->m_SipMsg.msg,dest);
	//osip_message_append_via(SipRegister->m_SipMsg.msg,dest);
	osip_free(dest);	
	osip_message_set_content_type(SipRegister->m_SipMsg.msg,"Application/DDCP");
	size_t length;
	int m=-1;
	m = osip_message_to_str(SipRegister->m_SipMsg.msg,&dest,&length);
	string st = dest;
	int index = st.find("From");
	//st.insert(index,cst);

	strcpy(*strRegister,st.c_str()/*dest*/);
	osip_free(dest);
	return m;	
}

int CSipMsgProcess::SipRegisterWithAuthCreate(char **strRegister,InfoServer m_InfoServer,InfoClient m_InfoClient,osip_message_t *srcmsg)
{	
	char FromTag[10];
	char CallID[10];
	//远程配置信息
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//本地配置信息
	char *srcCode=(LPSTR)(LPCTSTR)m_InfoClient.UserAddress;
	char *srcUserName=(LPSTR)(LPCTSTR)m_InfoClient.UserName;
	char *srcIP=(LPSTR)(LPCTSTR)m_InfoClient.IP;
	char *srcPort=(LPSTR)(LPCTSTR)m_InfoClient.Port;	
	int RandData;
	srand((unsigned int)time(0));
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(FromTag,str);
	RandData=rand();
	itoa(RandData,str,10);
	strcpy(CallID,str);

	char *dest;
	CSipMsgProcess *SipRegister=new CSipMsgProcess;
	////////////////////////
	osip_uri_set_host(SipRegister->m_SipMsg.uriServer,dstIP);
	osip_uri_set_scheme(SipRegister->m_SipMsg.uriServer,"sip");
	osip_uri_set_username(SipRegister->m_SipMsg.uriServer,dstCode);
	osip_uri_set_port(SipRegister->m_SipMsg.uriServer,dstPort);	

	osip_uri_set_host(SipRegister->m_SipMsg.uriClient,srcIP);
	osip_uri_set_scheme(SipRegister->m_SipMsg.uriClient,"sip");
	osip_uri_set_username(SipRegister->m_SipMsg.uriClient,srcCode);
	osip_uri_set_port(SipRegister->m_SipMsg.uriClient,srcPort);

	osip_via_set_version(SipRegister->m_SipMsg.via,"2.0");
	osip_via_set_protocol(SipRegister->m_SipMsg.via,"UDP");
	osip_via_set_port(SipRegister->m_SipMsg.via,srcPort);
	//osip_via_set_branch(SipRegister->m_SipMsg.via,"z9hG4bK--22bd7222");//随机数
// 	RandData=rand();	
// 	char sdtr[10];	
// 	char branch[20];
// 	itoa(RandData,sdtr,16);
// 	strcpy(branch,"z9hG4bK--");
// 	strcat(branch,sdtr);
// 	osip_via_set_branch(SipRegister->m_SipMsg.via,branch);//随机数
	osip_via_set_host(SipRegister->m_SipMsg.via,srcIP);

	osip_call_id_set_host(SipRegister->m_SipMsg.callid,srcIP);
	osip_call_id_set_number(SipRegister->m_SipMsg.callid,CallID);//随机数
	//保留本注册的消息的CallID信息
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	strcpy(pWnd->RegisterCallID.Host,srcIP);
	strcpy(pWnd->RegisterCallID.Num,CallID);

	osip_from_set_displayname(SipRegister->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipRegister->m_SipMsg.from,FromTag);//随机数
	osip_from_set_url(SipRegister->m_SipMsg.from,SipRegister->m_SipMsg.uriClient);
	strcpy(pWnd->RegisterCallID.Tag,FromTag);

	osip_to_set_displayname(SipRegister->m_SipMsg.to,srcUserName);	
	osip_to_set_url(SipRegister->m_SipMsg.to,SipRegister->m_SipMsg.uriClient);

	osip_cseq_set_method(SipRegister->m_SipMsg.cseq,"REGISTER");
	osip_cseq_set_number(SipRegister->m_SipMsg.cseq,"2");

	osip_message_set_uri(SipRegister->m_SipMsg.msg,SipRegister->m_SipMsg.uriServer);
	osip_message_set_method(SipRegister->m_SipMsg.msg,"REGISTER");

	osip_contact_set_url(SipRegister->m_SipMsg.contact,SipRegister->m_SipMsg.uriClient);
	//osip_contact_set_displayname(SipRegister->m_SipMsg.contact,srcUserName);
	osip_message_set_expires(SipRegister->m_SipMsg.msg,"60");
	osip_message_set_max_forwards(SipRegister->m_SipMsg.msg,"70");
	//osip_message_set_content_length(SipRegister->m_SipMsg.msg,"0");

	osip_call_id_to_str(SipRegister->m_SipMsg.callid,&dest);
	osip_message_set_call_id(SipRegister->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_from_to_str(SipRegister->m_SipMsg.from,&dest);
	osip_message_set_from(SipRegister->m_SipMsg.msg,dest);	
	osip_free(dest);

	osip_to_to_str(SipRegister->m_SipMsg.to,&dest);
	osip_message_set_to(SipRegister->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_contact_to_str(SipRegister->m_SipMsg.contact,&dest);
	osip_message_set_contact(SipRegister->m_SipMsg.msg,dest);
	strcpy(pWnd->contact,dest);
	osip_free(dest);

	osip_cseq_to_str(SipRegister->m_SipMsg.cseq,&dest);
	osip_message_set_cseq(SipRegister->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_via_to_str(SipRegister->m_SipMsg.via,&dest);
	osip_message_set_via(SipRegister->m_SipMsg.msg,dest);
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
	CString st0;
	if (1==i)
	{
		
		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(SipRegister->m_SipMsg.msg,dest);
		st0=dest;
		st0="Via: "+st0+"\r\n";		
	}
	else
	{
		st0="";
	}

	osip_free(dest);	
	osip_message_set_content_type(SipRegister->m_SipMsg.msg,"Application/DDCP");
	// 	osip_list siplist;

	char HA1[16*2 + 1];
	char HA2[16*2 + 1];
	char response[16*2 + 1];
	{
		//HA1=MD5(A1)=MD5(user:realm:password) ---->RFC2069
		md5_state_t state;
		md5_byte_t digest[16];		
		int di;
		md5_init(&state);
		CString cstrGroup=g_authInfo.username.c_str();
		cstrGroup+=":";
		cstrGroup+=g_authInfo.realm.c_str();
		cstrGroup+=":";
		cstrGroup+=g_authInfo.password.c_str();
		md5_append(&state, (const md5_byte_t *)(cstrGroup.GetBuffer(cstrGroup.GetLength())), cstrGroup.GetLength());
		md5_finish(&state, digest);
		for (di = 0; di < 16; ++di)
			sprintf(HA1 + di * 2, "%02x", digest[di]);
	}
	{
		//HA2=MD5(A2)=MD5(method:digestURI) ---->RFC2069
		md5_state_t state;
		md5_byte_t digest[16];
		int di;
		md5_init(&state);
		CString cstrGroup="REGISTER:";
		cstrGroup+=g_authInfo.uri.c_str();
		md5_append(&state, (const md5_byte_t *)(cstrGroup.GetBuffer(cstrGroup.GetLength())), cstrGroup.GetLength());
		md5_finish(&state, digest);
		for (di = 0; di < 16; ++di)
			sprintf(HA2 + di * 2, "%02x", digest[di]);
	}
	{
		//response=MD5(HA1:nonce:HA2) ---->RFC2069
		//response=MD5(HA1:nonce:nc:cnoce:HA2) ---->RFC2617
		md5_state_t state;
		md5_byte_t digest[16];
		int di;
		md5_init(&state);
		g_authInfo.nc="00000001";
		g_authInfo.cnonce="0k4f413b";
		//CString cstrGroup=CString(HA1)+":"+CString(g_authInfo.nonce.c_str())+":"+CString(HA2);
		CString cstrGroup=CString(HA1)+":"+CString(g_authInfo.nonce.c_str())+":"+CString(g_authInfo.nc.c_str())+":"+CString(g_authInfo.cnonce.c_str())+":"+CString(HA2);
		md5_append(&state, (const md5_byte_t *)(cstrGroup.GetBuffer(cstrGroup.GetLength())), cstrGroup.GetLength());
		md5_finish(&state, digest);
		for (di = 0; di < 16; ++di)
			sprintf(response + di * 2, "%02x", digest[di]);
	}
	//printf("%s",hex_output);
	//CString cstr=CString("Authorization: Digest username=\"")+g_authInfo.username.c_str()+"\",realm=\""+g_authInfo.realm.c_str()+"\",nonce=\""+g_authInfo.nonce.c_str()+"\",uri=\""+g_authInfo.uri.c_str()+"\",response=\""+response+"\",algorithm=MD5,opaque=\"\"\r\n";
	CString cstr=CString("Authorization: Digest username=\"")+g_authInfo.username.c_str()+"\",realm=\""+g_authInfo.realm.c_str()+"\",nonce=\""+g_authInfo.nonce.c_str()+"\",uri=\""+g_authInfo.uri.c_str()+"\",nc=\""+g_authInfo.nc.c_str()+"\",cnonce=\""+g_authInfo.cnonce.c_str()+"\",response=\""+response+"\",algorithm=MD5,opaque=\"\"\r\n";
	string st=cstr.GetBuffer(0);
	size_t length;
	int m=-1;
	m = osip_message_to_str(SipRegister->m_SipMsg.msg,&dest,&length);
	
	string strtemp=dest;
	int index=strtemp.find("Content-Length");
	strtemp.insert(index,st);
	//index=strtemp.find("From");
	//strtemp.insert(index,st0.GetBuffer(st0.GetLength()));

	TRACE(strtemp.c_str());
	strcpy(*strRegister,strtemp.c_str());
	osip_free(dest);
	return m;	
}

void CSipMsgProcess::XmlNodeCreate(char** strNodeXml)
{
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	CString strTemp;
	strTemp ="<?xml version=\"1.0\"?>\r\n";
	strTemp += "<Action>\r\n";
	strTemp += "<Variable>Catalog</Variable>\r\n";
	strTemp += "<Parent>"+pWnd->m_InfoClient.UserAddress+"</Parent>\r\n";	
	strTemp += "<SubNum>2</SubNum>\r\n";
	strTemp += "<SubList>\r\n";

	//Encoder 01
	strTemp += "<Item>\r\n";
	strTemp += "<Name>Encoder 01</Name>\r\n";
	strTemp += "<Address>252000001101001001</Address>\r\n";
	strTemp += "<Privilege>%11%01</Privilege>\r\n";
	strTemp += "<SeriesNumber>000000000123</SeriesNumber>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>10</Longitude>\r\n";
	strTemp += "<Latitude>10</Latitude>\r\n";
	strTemp += "<Elevation>10</Elevation>\r\n";	
	strTemp += "<Roadway>10</Roadway>\r\n";
	strTemp += "<PileNo>10</PileNo>\r\n";
	strTemp += "<Manufacturer>海康威视</Manufacturer>\r\n";
	strTemp += "<Model>10</Model>\r\n";
	strTemp += "<Chip>10</Chip>\r\n";
	strTemp += "<OperateType>ADD</OperateType>\r\n";
	strTemp += "</Item>\r\n";
	pWnd->m_Invite.m_address.AddString("Encoder 01");
	pWnd->m_Invite.address.push_back("252000001101001001");

	//IPC 01
	strTemp += "<Item>\r\n";
	strTemp += "<Name>IPC 01</Name>\r\n";
	strTemp += "<Address>252000001102001001</Address>\r\n";
	strTemp += "<Privilege>%11%02</Privilege>\r\n";
	strTemp += "<SeriesNumber>000000000213</SeriesNumber>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>20</Longitude>\r\n";
	strTemp += "<Latitude>20</Latitude>\r\n";
	strTemp += "<Roadway>20</Roadway>\r\n";			
	strTemp += "<Elevation>20</Elevation>\r\n";
	strTemp += "<PileNo>20</PileNo>\r\n";
	strTemp += "<Manufacturer>海康威视</Manufacturer>\r\n";
	strTemp += "<Model>20</Model>\r\n";
	strTemp += "<Chip>20</Chip>\r\n";
	strTemp += "<OperateType>ADD</OperateType>\r\n";
	strTemp += "</Item>\r\n";
	pWnd->m_Invite.m_address.AddString("IPC 01");
	pWnd->m_Invite.address.push_back("252000001102001001");

	//Subnode 01
	strTemp += "<Item>\r\n";
	strTemp += "<Name>Subnode 01</Name>\r\n";
	strTemp += "<Address>252000001103001001</Address>\r\n";
	strTemp += "<Privilege>%11%03</Privilege>\r\n";
	strTemp += "<SeriesNumber>000000000313</SeriesNumber>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>30</Longitude>\r\n";
	strTemp += "<Latitude>30</Latitude>\r\n";
	strTemp += "<Roadway>30</Roadway>\r\n";
	strTemp += "<Elevation>30</Elevation>\r\n";
	//<道路名称和位置桩号可不填>
	strTemp += "<OperateType>ADD</OperateType>\r\n";
	strTemp += "</Item>\r\n";
	pWnd->m_Invite.m_address.AddString("Subnode 01");
	pWnd->m_Invite.address.push_back("252000001103001001");

	//DVR 01
	strTemp += "<Item>\r\n";
	strTemp += "<Name>DVR 01</Name>\r\n";
	strTemp += "<Address>252000001104001001</Address>\r\n";
	strTemp += "<Privilege>%11%04</Privilege>\r\n";
	strTemp += "<SeriesNumber>000000000413</SeriesNumber>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>40</Longitude>\r\n";
	strTemp += "<Latitude>40</Latitude>\r\n";
	strTemp += "<Elevation>40</Elevation>\r\n";
	strTemp += "<Roadway>40</Roadway>\r\n";
	strTemp += "<PileNo>10</PileNo>\r\n";
	strTemp += "<TotalSpace>254312MB</TotalSpace>\r\n";
	strTemp += "<MaxVOD>4</MaxVOD>\r\n";
	strTemp += "<Manufacturer>海康威视</Manufacturer>\r\n";
	strTemp += "<Model>40</Model>\r\n";
	strTemp += "<Chip>40</Chip>\r\n";
	strTemp += "<FreeSpace>20480</FreeSpace>\r\n";
	strTemp += "<CurrentRecord>16</CurrentRecord>\r\n";
	strTemp += "<CurrentVOD>3</CurrentVOD>\r\n";
	strTemp += "<CameraAddress>000000001104001001</CameraAddress>\r\n";
	strTemp += "<CameraAddress>000000001104002001</CameraAddress>\r\n";
	strTemp += "<CameraAddress>000000001104003001</CameraAddress>\r\n";

	strTemp += "<OperateType>ADD</OperateType>\r\n";
	strTemp += "</Item>\r\n";
	pWnd->m_Invite.m_address.AddString("DVR 01");
	pWnd->m_Invite.address.push_back("252000001104001001");

	strTemp += "</SubList>\r\n";
	strTemp += "</Action>\r\n";
	char *str=(LPSTR)(LPCTSTR)strTemp;
	strcpy(*strNodeXml,str);
}

void CSipMsgProcess::XmlNodeCreate1(char** strNodeXml)
{
	HWND   hnd = ::FindWindow(NULL, _T("UAC"));
	CUACDlg*  pWnd = (CUACDlg*)CWnd::FromHandle(hnd);
	CString strTemp;
	strTemp = "<?xml version=\"1.0\"?>\r\n";
	strTemp += "<Action>\r\n";
	strTemp += "<Variable>Catalog</Variable>\r\n";
	strTemp += "<Parent>" + pWnd->m_InfoClient.UserAddress + "</Parent>\r\n";
	strTemp += "<SubNum>2</SubNum>\r\n";
	strTemp += "<SubList>\r\n";
	//<！--推送吧编码器下所连接的模拟相机信息-->
	//Cam 01
	strTemp += "<Item>\r\n";
	strTemp += "<Name>Cam 01</Name>\r\n";
	strTemp += "<Address>252000001201001001</Address>\r\n";//1201001001
	strTemp += "<Privilege>%12%01</Privilege>\r\n";
	strTemp += "<SeriesNumber>000000000201</SeriesNumber>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>10</Longitude>\r\n";
	strTemp += "<Latitude>10</Latitude>\r\n";
	strTemp += "<Elevation>10</Elevation>\r\n";
	strTemp += "<Roadway>10</Roadway>\r\n";
	strTemp += "<PileNo>10</PileNo>\r\n";
	strTemp += "<Manufacturer>海康威视</Manufacturer>\r\n";
	strTemp += "<Model>10</Model>\r\n";
	strTemp += "<Chip>10</Chip>\r\n";
	strTemp += "<OperateType>ADD</OperateType>\r\n";
	strTemp += "</Item>\r\n";
	pWnd->m_Invite.m_address.AddString("Cam 01");
	pWnd->m_Invite.address.push_back("252000001201001001");
	//Cam 02
	strTemp += "<Item>\r\n";
	strTemp += "<Name>Cam 02</Name>\r\n";
	strTemp += "<Address>252000001202001001</Address>\r\n";//1202001001
	strTemp += "<Privilege>%12%02</Privilege>\r\n";
	strTemp += "<SeriesNumber>000000000202</SeriesNumber>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>20</Longitude>\r\n";
	strTemp += "<Latitude>20</Latitude>\r\n";
	strTemp += "<Elevation>20</Elevation>\r\n";
	strTemp += "<Roadway>20</Roadway>\r\n";
	strTemp += "<PileNo>20</PileNo>\r\n";
	strTemp += "<Manufacturer>海康威视</Manufacturer>\r\n";
	strTemp += "<Model>20</Model>\r\n";
	strTemp += "<Chip>20</Chip>\r\n";
	strTemp += "<OperateType>ADD</OperateType>\r\n";
	strTemp += "</Item>\r\n";
	pWnd->m_Invite.m_address.AddString("Cam 02");
	pWnd->m_Invite.address.push_back("252000001202001001");
	strTemp += "</SubList>\r\n";
	strTemp += "</Action>\r\n";
	char *str = (LPSTR)(LPCTSTR)strTemp;
	strcpy(*strNodeXml, str);
}

void CSipMsgProcess::XmlNodeCreate2(char** strNodeXml)
{
	HWND   hnd = ::FindWindow(NULL, _T("UAC"));
	CUACDlg*  pWnd = (CUACDlg*)CWnd::FromHandle(hnd);
	CString strTemp;
	strTemp = "<?xml version=\"1.0\"?>\r\n";
	strTemp += "<Action>\r\n";
	strTemp += "<Variable>Catalog</Variable>\r\n";
	strTemp += "<Parent>" + pWnd->m_InfoClient.UserAddress + "</Parent>\r\n";
	strTemp += "<SubNum>2</SubNum>\r\n";
	strTemp += "<SubList>\r\n";
	//<！--推送吧编码器下所连接的模拟相机信息-->
	//Cam 01
	strTemp += "<Item>\r\n";
	strTemp += "<Name>Cam 01</Name>\r\n";
	strTemp += "<Address>252000001201001001</Address>\r\n";//1201001001
	strTemp += "<Privilege>%12%01</Privilege>\r\n";
	strTemp += "<SeriesNumber>000000000201</SeriesNumber>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>10</Longitude>\r\n";
	strTemp += "<Latitude>10</Latitude>\r\n";
	strTemp += "<Elevation>10</Elevation>\r\n";
	strTemp += "<Roadway>10</Roadway>\r\n";
	strTemp += "<PileNo>10</PileNo>\r\n";
	strTemp += "<Manufacturer>海康威视</Manufacturer>\r\n";
	strTemp += "<Model>10</Model>\r\n";
	strTemp += "<Chip>10</Chip>\r\n";
	strTemp += "<OperateType>ADD</OperateType>\r\n";
	strTemp += "</Item>\r\n";
	pWnd->m_Invite.m_address.AddString("Cam 01");
	pWnd->m_Invite.address.push_back("252000001201001001");
	//Cam 02
	strTemp += "<Item>\r\n";
	strTemp += "<Name>Cam 02</Name>\r\n";
	strTemp += "<Address>252000001202001001</Address>\r\n";//1202001001
	strTemp += "<Privilege>%12%02</Privilege>\r\n";
	strTemp += "<SeriesNumber>000000000202</SeriesNumber>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>20</Longitude>\r\n";
	strTemp += "<Latitude>20</Latitude>\r\n";
	strTemp += "<Elevation>20</Elevation>\r\n";
	strTemp += "<Roadway>20</Roadway>\r\n";
	strTemp += "<PileNo>20</PileNo>\r\n";
	strTemp += "<Manufacturer>海康威视</Manufacturer>\r\n";
	strTemp += "<Model>20</Model>\r\n";
	strTemp += "<Chip>20</Chip>\r\n";
	strTemp += "<OperateType>ADD</OperateType>\r\n";
	strTemp += "</Item>\r\n";
	pWnd->m_Invite.m_address.AddString("Cam 02");
	pWnd->m_Invite.address.push_back("252000001202001001");
	strTemp += "</SubList>\r\n";
	strTemp += "</Action>\r\n";
	char *str = (LPSTR)(LPCTSTR)strTemp;
	strcpy(*strNodeXml, str);
}

void CSipMsgProcess::SipNodeXmlMsg(char **strNode,InfoServer m_InfoServer,InfoClient m_InfoClient,char *NodeXml,osip_message_t *srcmsg)
{
	char FromTag[10];
	char CallID[10];
	//远程配置信息
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//本地配置信息
	char *srcCode=(LPSTR)(LPCTSTR)m_InfoClient.UserAddress;
	char *srcUserName=(LPSTR)(LPCTSTR)m_InfoClient.UserName;
	char *srcIP=(LPSTR)(LPCTSTR)m_InfoClient.IP;
	char *srcPort=(LPSTR)(LPCTSTR)m_InfoClient.Port;	
	int RandData;
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(FromTag,str);
	RandData=rand();
	itoa(RandData,str,10);
	strcpy(CallID,str);

	char *dest;
	CSipMsgProcess *SipNode=new CSipMsgProcess;
	////////////////////////
	osip_uri_set_host(SipNode->m_SipMsg.uriServer,dstIP);
	osip_uri_set_scheme(SipNode->m_SipMsg.uriServer,"sip");
	osip_uri_set_username(SipNode->m_SipMsg.uriServer,dstCode);
	osip_uri_set_port(SipNode->m_SipMsg.uriServer,dstPort);	

	osip_uri_set_host(SipNode->m_SipMsg.uriClient,srcIP);
	osip_uri_set_scheme(SipNode->m_SipMsg.uriClient,"sip");
	osip_uri_set_username(SipNode->m_SipMsg.uriClient,srcCode);
	osip_uri_set_port(SipNode->m_SipMsg.uriClient,srcPort);

	osip_via_set_version(SipNode->m_SipMsg.via,"2.0");
	osip_via_set_protocol(SipNode->m_SipMsg.via,"UDP");
	osip_via_set_port(SipNode->m_SipMsg.via,srcPort);

 	char branch[20] = "z9hG4bK";
	for (int i = 0; i < 8; i++)
	{
		RandData = rand() % 10;
		branch[i+7] = RandData + '0';
	}
	osip_via_set_branch(SipNode->m_SipMsg.via, branch);//随机数
	osip_via_set_host(SipNode->m_SipMsg.via,srcIP);

	osip_call_id_set_host(SipNode->m_SipMsg.callid,srcIP);
	osip_call_id_set_number(SipNode->m_SipMsg.callid,CallID);//随机数
	//保留本注册的消息的CallID信息
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	strcpy(pWnd->NodeTypeCallID.Host,srcIP);
	strcpy(pWnd->NodeTypeCallID.Num,CallID);

	//osip_from_set_displayname(SipNode->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipNode->m_SipMsg.from,FromTag);//随机数
	osip_from_set_url(SipNode->m_SipMsg.from,SipNode->m_SipMsg.uriClient);
	strcpy(pWnd->NodeTypeCallID.Tag,FromTag);

	//osip_to_set_displayname(SipNode->m_SipMsg.to,dstUserName);	
	osip_to_set_url(SipNode->m_SipMsg.to,SipNode->m_SipMsg.uriServer);

	osip_cseq_set_method(SipNode->m_SipMsg.cseq,"NOTIFY");
	osip_cseq_set_number(SipNode->m_SipMsg.cseq,"1");

	osip_message_set_uri(SipNode->m_SipMsg.msg,SipNode->m_SipMsg.uriServer);
	osip_message_set_method(SipNode->m_SipMsg.msg,"NOTIFY");

	osip_contact_set_url(SipNode->m_SipMsg.contact,SipNode->m_SipMsg.uriClient);
	osip_contact_set_displayname(SipNode->m_SipMsg.contact,srcUserName);
	osip_message_set_max_forwards(SipNode->m_SipMsg.msg,"70");

	osip_to_to_str(SipNode->m_SipMsg.to,&dest);
	osip_message_set_to(SipNode->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_call_id_to_str(SipNode->m_SipMsg.callid,&dest);
	osip_message_set_call_id(SipNode->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_from_to_str(SipNode->m_SipMsg.from,&dest);
	osip_message_set_from(SipNode->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_contact_to_str(SipNode->m_SipMsg.contact,&dest);
	osip_message_set_contact(SipNode->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_cseq_to_str(SipNode->m_SipMsg.cseq,&dest);
	osip_message_set_cseq(SipNode->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_via_to_str(SipNode->m_SipMsg.via,&dest);
	osip_message_set_via(SipNode->m_SipMsg.msg,dest);
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	int i = osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
	CString st0;
	if (1==i)
	{

		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(SipNode->m_SipMsg.msg,dest);
		st0=dest;
		st0="Via: "+st0+"\r\n";		
	}
	else
	{
		st0="";
	}
	osip_free(dest);	
	osip_message_set_content_type(SipNode->m_SipMsg.msg,"Application/DDCP");
	osip_message_set_body(SipNode->m_SipMsg.msg,NodeXml,strlen(NodeXml));
	size_t length;
	osip_message_to_str(SipNode->m_SipMsg.msg,&dest,&length);	
	strcpy(*strNode,dest);
	osip_free(dest);
}

int CSipMsgProcess::SipParser(char *buffer,int Msglength)
{
	int beginIndex=0;
	int endIndex=0;
	if (OSIP_SUCCESS != osip_message_init(&m_SipMsg.msg))
	{
		AfxMessageBox("OSIP解析初始化失败",MB_OK|MB_ICONERROR);
		return 1;
	}
	int i=osip_message_parse(m_SipMsg.msg,buffer,Msglength);

	//m_SipMsg.msg->message = buffer;//初始化mes->message,以获取expires，max_forward等

	if (i!=OSIP_SUCCESS)
	{	
		AfxMessageBox("SIP消息解析错误",MB_OK|MB_ICONERROR);
		return 1;		
	}
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);	
	char *Alarmtemp=NULL;
	if (m_SipMsg.msg->call_id->host==NULL)
	{		
		osip_call_id_to_str(m_SipMsg.msg->call_id,&Alarmtemp);
		m_SipMsg.msg->call_id->host="";
	}
	if (m_SipMsg.msg->call_id->number==NULL)
	{
		m_SipMsg.msg->call_id->number="";
		if (m_SipMsg.msg->call_id->host==NULL)
		{
			m_SipMsg.msg->call_id->host="";
			AfxMessageBox("SIP消息无Call ID字段",MB_OK|MB_ICONERROR);
			return 0;
		}		
	}	
	char *XmlMessage=new char[XMLSIZE];
	memset(XmlMessage,0,XMLSIZE);
	//判断事件类型
	if (  strcmp(m_SipMsg.msg->call_id->host,pWnd->RegisterCallID.Host)==0 	&&
		strcmp(m_SipMsg.msg->call_id->number,pWnd->RegisterCallID.Num)==0  )
	{		
		//receive register message
		if ( !RegisterSipVerify(pWnd->m_InfoServer,pWnd->m_InfoClient,m_SipMsg.msg,1))
		{
			AfxMessageBox("Register From 或 To字段校验不通过",MB_OK|MB_ICONERROR);
			delete XmlMessage;
			return 0;
		}
		if (m_SipMsg.msg->from->gen_params.nb_elt==0 )
		{
			AfxMessageBox("from must include tag",MB_OK|MB_ICONEXCLAMATION);
			delete XmlMessage;
			return 0;
		}
		osip_uri_param_t *h;
		osip_uri_param_init(&h);
		osip_from_get_tag(m_SipMsg.msg->from,&h);
		char Tag[10];
		strcpy(Tag,h->gvalue);
		osip_uri_param_free(h);
		if (strcmp(Tag,pWnd->RegisterCallID.Tag)==0)
		{
			m_Type=Register;	
		}
		else
		{
			AfxMessageBox("Tag is error",MB_OK|MB_ICONERROR);
			delete XmlMessage;
			return 0;
		}
	}
	else if (MSG_IS_INVITE(m_SipMsg.msg))
	{	
		//receive invite message from sever		
		m_Type=Invite;				
		//update log
		pWnd->ShowTestLogData="<--------  INVITE\r\n";			
		pWnd->ShowTestLogTitle="Invite Test";		
	}
	else if (MSG_IS_CANCEL(m_SipMsg.msg))
	{	
		//receive invite message from sever		
		m_Type=CANCEL;				
		//update log
		pWnd->ShowTestLogData="<--------  CANCEL\r\n";			
		pWnd->ShowTestLogTitle="Invite Test";		
	}
	else if (MSG_IS_ACK(m_SipMsg.msg))
	{
		//receive ACK message from sever	
		pWnd->bACK=TRUE;
		//update log
		pWnd->ShowTestLogData+="<--------  ACK\r\n";		
		SipBYE(&pWnd->byestring,m_SipMsg.msg);
		pWnd->m_Invite.GetDlgItem(IDC_BTN_BYE)->EnableWindow(TRUE);
		delete XmlMessage;		
		return 0;
	}
	else if (MSG_IS_BYE(m_SipMsg.msg))
	{		
		pWnd->bBYE=TRUE;
		pWnd->bACK=FALSE;
		char *dst=new char[MAXBUFSIZE];
		//Send sip 200 ok		
		char *dest=NULL;
		size_t len;
		CSipMsgProcess *Sip200=new CSipMsgProcess;
		osip_message_set_version(Sip200->m_SipMsg.msg,"SIP/2.0");
		osip_message_set_status_code(Sip200->m_SipMsg.msg,200);
		osip_message_set_reason_phrase(Sip200->m_SipMsg.msg,"OK");
		osip_call_id_clone(m_SipMsg.msg->call_id,&Sip200->m_SipMsg.msg->call_id);		
		osip_from_clone(m_SipMsg.msg->from,&Sip200->m_SipMsg.msg->from);
		osip_to_clone(m_SipMsg.msg->to,&Sip200->m_SipMsg.msg->to);
		osip_cseq_clone(m_SipMsg.msg->cseq,&Sip200->m_SipMsg.msg->cseq);
		//copy via
		osip_message_get_via(m_SipMsg.msg,0,&Sip200->m_SipMsg.via);
		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);
		/*osip_via_set_version(Sip200->m_SipMsg.via,"2.0");
		osip_via_set_protocol(Sip200->m_SipMsg.via,"UDP");
		osip_via_set_port(Sip200->m_SipMsg.via,m_SipMsg.msg->from->url->port);	
		osip_via_set_host(Sip200->m_SipMsg.via,m_SipMsg.msg->from->url->host);		
		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);*/
		osip_message_set_max_forwards(Sip200->m_SipMsg.msg,"70");
		osip_message_to_str(Sip200->m_SipMsg.msg,&dest,&len);
		memset(dst,0,MAXBUFSIZE);
		memcpy(dst,dest,len);
		osip_free(dest);
		//Send Message
		//pWnd->SendData(dst);	
		UA_Msg uac_sendtemp;
		strcpy(uac_sendtemp.data,dst);
		EnterCriticalSection(&g_uac);
		uac_sendqueue.push(uac_sendtemp);
		LeaveCriticalSection(&g_uac);
		pWnd->m_Invite.GetDlgItem(IDC_BTN_BYE)->EnableWindow(FALSE);
		//pWnd->ShowSendData(dst);
		delete dst;			
	}
	/***********************************************************************/
	/*这里是各种"DO"请求的XML解析 writed by Bsp Lee                          */
	/***********************************************************************/
	else if (  m_SipMsg.msg->status_code==0 && strcmp(m_SipMsg.msg->sip_method,"DO")==0 )
	{		
		//analyse XML message
		osip_body_t *XMLbody;
		osip_body_init(&XMLbody);
		osip_message_get_body (m_SipMsg.msg, 0, &XMLbody);
		memcpy(XmlMessage,XMLbody->body,strlen(XMLbody->body));
		string strTemp(XmlMessage);		
		string temp;
		char var[50];
		string::size_type VariableStart;	
		string::size_type VariableEnd;		
		if( (VariableStart=strTemp.find("<Variable>",0)) ==string::npos)
		{
			delete XmlMessage;
			char *dst=new char[MAXBUFSIZE];
			Sip400(&dst,m_SipMsg.msg);
			//pWnd->SendData(dst);	
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dst);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);
			//pWnd->ShowSendData(dst);
			delete dst;			
			//update log
			pWnd->ShowTestLogData+="400 --------> \r\n";
			AfxMessageBox("缺少Variable字段");
			return 1;
		}						
		if ( (VariableEnd=strTemp.find("</Variable>",VariableStart+1)) ==string::npos)	
		{
			delete XmlMessage;
			char *dst=new char[MAXBUFSIZE];
			Sip400(&dst,m_SipMsg.msg);
			//pWnd->SendData(dst);	
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dst);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);
			//pWnd->ShowSendData(dst);
			delete dst;			
			//update log
			pWnd->ShowTestLogData+="400 --------> \r\n";
			AfxMessageBox("缺少Variable字段");
			return 1;
		}
		temp=strTemp.substr(VariableStart+10,VariableEnd-VariableStart-10);	
		strcpy(var,temp.c_str());
		temp.erase(0,temp.length());
		osip_body_free(XMLbody);				
		if (strcmp(var,"PTZCommand")==0)
		{
			m_Type=PTZ;
			pWnd->CurStatusID.nSataus=PTZ;
			//update log
			pWnd->ShowTestLogData=" <---------  DO  \r\n";		
			pWnd->ShowTestLogTitle="PTZ Test";
		}
		else if (strcmp(var,"PresetList")==0 )
		{//解析index
			if( (VariableStart=strTemp.find("<FromIndex>",0)) ==string::npos)
			{
				delete XmlMessage;
				char *dst=new char[MAXBUFSIZE];
				Sip400(&dst,m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;			
				//update log
				pWnd->ShowTestLogData+="400 --------> \r\n";
				AfxMessageBox("预置位查询，缺少FromIndex字段");
				return 1;
			}						
			if ( (VariableEnd=strTemp.find("</FromIndex>",VariableStart+1)) ==string::npos)	
			{
				delete XmlMessage;
				char *dst=new char[MAXBUFSIZE];
				Sip400(&dst,m_SipMsg.msg);
				//pWnd->SendData(dst);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dst);
				delete dst;			
				//update log
				pWnd->ShowTestLogData+="400 --------> \r\n";
				AfxMessageBox("预置位查询，缺少FromIndex字段");
				return 1;
			}
			temp=strTemp.substr(VariableStart+11,VariableEnd-VariableStart-11);	
			// 			strcpy(var,temp.c_str());
			// 			temp.erase(0,temp.length());
			beginIndex=atoi(temp.c_str());
			if( (VariableStart=strTemp.find("<ToIndex>",0)) ==string::npos)
			{
				delete XmlMessage;
				char *dst=new char[MAXBUFSIZE];
				Sip400(&dst,m_SipMsg.msg);
				//pWnd->SendData(dst);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dst);
				delete dst;			
				//update log
				pWnd->ShowTestLogData+="400 --------> \r\n";
				AfxMessageBox("预置位查询，缺少ToIndex字段");
				return 1;
			}						
			if ( (VariableEnd=strTemp.find("</ToIndex>",VariableStart+1)) ==string::npos)	
			{
				delete XmlMessage;
				char *dst=new char[MAXBUFSIZE];
				Sip400(&dst,m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;			
				//update log
				pWnd->ShowTestLogData+="400 --------> \r\n";
				AfxMessageBox("预置位查询，缺少ToIndex字段");
				return 1;
			}
			temp=strTemp.substr(VariableStart+9,VariableEnd-VariableStart-9);	
			// 			strcpy(var,temp.c_str());
			// 			temp.erase(0,temp.length());
			endIndex=atoi(temp.c_str());
			m_Type=PreBitSet;		
			pWnd->CurStatusID.nSataus=PreBitSet;
			//update log
			pWnd->ShowTestLogData=" <---------  DO  \r\n";		
			pWnd->ShowTestLogTitle="预置位查询";
		}
		else if (strcmp(var,"FileList")==0)
		{
			//解析index
			if( (VariableStart=strTemp.find("<FromIndex>",0)) ==string::npos)
			{
				delete XmlMessage;
				char *dst=new char[MAXBUFSIZE];
				Sip400(&dst,m_SipMsg.msg);
				//pWnd->SendData(dst);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dst);
				delete dst;			
				//update log
				pWnd->ShowTestLogData+="400 --------> \r\n";
				AfxMessageBox("录像查询缺少，FromIndex");
				return 1;
			}						
			if ( (VariableEnd=strTemp.find("</FromIndex>",VariableStart+1)) ==string::npos)	
			{
				delete XmlMessage;
				char *dst=new char[MAXBUFSIZE];
				Sip400(&dst,m_SipMsg.msg);
				//pWnd->SendData(dst);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dst);
				delete dst;			
				//update log
				pWnd->ShowTestLogData+="400 --------> \r\n";
				AfxMessageBox("录像查询缺少，FromIndex");
				return 1;
			}
			temp=strTemp.substr(VariableStart+11,VariableEnd-VariableStart-11);	
// 			strcpy(var,temp.c_str());
// 			temp.erase(0,temp.length());
			beginIndex=atoi(temp.c_str());
			if( (VariableStart=strTemp.find("<ToIndex>",0)) ==string::npos)
			{
				delete XmlMessage;
				char *dst=new char[MAXBUFSIZE];
				Sip400(&dst,m_SipMsg.msg);
				//pWnd->SendData(dst);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dst);
				delete dst;			
				//update log
				pWnd->ShowTestLogData+="400 --------> \r\n";
				AfxMessageBox("录像查询缺少，ToIndex");
				return 1;
			}						
			if ( (VariableEnd=strTemp.find("</ToIndex>",VariableStart+1)) ==string::npos)	
			{
				delete XmlMessage;
				char *dst=new char[MAXBUFSIZE];
				Sip400(&dst,m_SipMsg.msg);
				//pWnd->SendData(dst);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dst);
				delete dst;			
				//update log
				pWnd->ShowTestLogData+="400 --------> \r\n";
				AfxMessageBox("录像查询缺少，ToIndex");
				return 1;
			}
			temp=strTemp.substr(VariableStart+9,VariableEnd-VariableStart-9);	
			// 			strcpy(var,temp.c_str());
			// 			temp.erase(0,temp.length());
			endIndex=atoi(temp.c_str());

			m_Type=HistoryQuery;
			//Update log
			pWnd->ShowTestLogData="<--------- DO\r\n";			
			pWnd->ShowTestLogTitle="History Video Query Test";
		}
		else if (strcmp(var,"ItemList")==0)
		{
			m_Type=CatalogQuery;			
			//Update log
			pWnd->ShowTestLogData="<--------- DO\r\n";			
			pWnd->ShowTestLogTitle="Catalog Query Test";
		}
		else if (strcmp(var,"DeviceInfo")==0)
		{
			m_Type=DeviceInfQuery;			
			//Update log
			pWnd->ShowTestLogData="<--------- DO\r\n";			
			pWnd->ShowTestLogTitle="Catalog Query Test";
		}
		else if (strcmp(var,"BandWidth")==0)
		{
			m_Type=FlowQuery;			
			//Update log
			pWnd->ShowTestLogData="<--------- DO\r\n";			
			pWnd->ShowTestLogTitle="Catalog Query Test";
		}
		else if (strcmp(var,"VODByRTSP")==0)
		{
			m_Type=HistoryPlay;			
			//Update log
			pWnd->ShowTestLogData="<---------- DO\r\n";		
			pWnd->ShowTestLogTitle="Get History Video URL Test";
		}
		else if (strcmp(var,"EncoderSet")==0 )
		{
			m_Type=EncoderSet;
			pWnd->CurStatusID.nSataus=EncoderSet;
			//update log
			pWnd->ShowTestLogData=" <--------  DO \r\n";		
			pWnd->ShowTestLogTitle="Encoder Set Test";
		}
		else if (strcmp(var,"TimeSet")==0 )
		{
			m_Type=TimeSet;
			pWnd->CurStatusID.nSataus=TimeSet;
			//update log
			pWnd->ShowTestLogData=" <--------  DO \r\n";		
			pWnd->ShowTestLogTitle="Time Set Test";
		}
		else if (strcmp(var,"RealTimeKeepAlive")==0 )
		{		
			pWnd->bRealTimeFlag=TRUE;
			char *dst=new char[MAXBUFSIZE];
			Sip200OK(&dst,m_SipMsg.msg);				
			//pWnd->SendData(dst);
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dst);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);
			delete dst;
			delete XmlMessage;					
			return 0;			
		}
		else
		{
			delete XmlMessage;
			return 1;
		}
	}
	else if (MSG_IS_SUBSCRIBE(m_SipMsg.msg))
	{
		//receive subscribe message from sever		
		m_Type=Alarm;		
		pWnd->balarmsubscribe=TRUE;
		//update log
		pWnd->ShowTestLogData="<--------  SUBSCRIBE\r\n";			
		pWnd->ShowTestLogTitle="Alarm Subscribe Test";
	}
	else if ( strcmp(m_SipMsg.msg->call_id->host,pWnd->KeepAliveID.Host)==0 && 
		strcmp(m_SipMsg.msg->call_id->number,pWnd->KeepAliveID.Num)==0 )
	{
		//receive keepAlive message
		if ( !SipVerify(pWnd->m_InfoServer,pWnd->m_InfoClient,m_SipMsg.msg,1))
		{
			AfxMessageBox("KeepAlive From or To variable is error",MB_OK|MB_ICONERROR);
			delete XmlMessage;
			return 0;
		}
		if (m_SipMsg.msg->from->gen_params.nb_elt==0 )
		{
			AfxMessageBox("from must include tag",MB_OK|MB_ICONEXCLAMATION);
			delete XmlMessage;
			return 0;
		}
		osip_uri_param_t *h;
		osip_uri_param_init(&h);
		osip_from_get_tag(m_SipMsg.msg->from,&h);
		char Tag[10];
		strcpy(Tag,h->gvalue);
		osip_uri_param_free(h);
		if (strcmp(Tag,pWnd->KeepAliveID.Tag)==0)
		{
			delete XmlMessage;
			if (pWnd->bSipRegister)
			{
				return 0;
			}
			else
			{
				pWnd->bSipRegister=TRUE;
				return 0;
			}
		}
		else
		{
			AfxMessageBox(" KeepAlive Tag is error",MB_OK|MB_ICONERROR);
			delete XmlMessage;
			return 0;
		}
	}
	else if ( strcmp(m_SipMsg.msg->call_id->host,pWnd->NodeTypeCallID.Host)==0 && 
		strcmp(m_SipMsg.msg->call_id->number,pWnd->NodeTypeCallID.Num)==0 )
	{		
		// receive node message
		if ( !SipVerify(pWnd->m_InfoServer,pWnd->m_InfoClient,m_SipMsg.msg,1))
		{
			AfxMessageBox("Node Send From or To is error",MB_OK|MB_ICONERROR);
			delete XmlMessage;
			return 0;
		}
		if (m_SipMsg.msg->from->gen_params.nb_elt==0 )
		{
			AfxMessageBox("from variable must include tag",MB_OK|MB_ICONEXCLAMATION);
			delete XmlMessage;
			return 0;
		}
		osip_uri_param_t *h;
		osip_uri_param_init(&h);
		osip_from_get_tag(m_SipMsg.msg->from,&h);
		char Tag[10];
		strcpy(Tag,h->gvalue);
		osip_uri_param_free(h);
		if (strcmp(Tag,pWnd->NodeTypeCallID.Tag)==0)
		{
			m_Type=NodeType;	
		}
		else
		{
			AfxMessageBox("Tag is error",MB_OK|MB_ICONERROR);
			delete XmlMessage;
			return 0;
		}		
	}
	else
	{
		if (Alarmtemp==NULL)
		{
			Alarmtemp=new char[100];
			strcpy(Alarmtemp,m_SipMsg.msg->call_id->number);
			strcat(Alarmtemp,"@");
			strcat(Alarmtemp,m_SipMsg.msg->call_id->host);
		}
		if (strcmp(Alarmtemp,pWnd->AlarmCallID)==0)
		{
			if ( m_SipMsg.msg->status_code==200 )
			{
				pWnd->ShowTestLogData+="<---------- 200 OK\r\n";
				osip_body_t *XMLbody;
				osip_body_init(&XMLbody);
				int m=10;
				m=osip_message_get_body (m_SipMsg.msg, 0, &XMLbody);
				osip_body_free(XMLbody);
				if ( m==0 )
				{
					//alarm notify send
				}
				else
				{
					pWnd->m_Alarm.GetDlgItem(IDC_BTN_ALARM_NOTIFY)->EnableWindow(TRUE);
				}				
			}
			else if ( m_SipMsg.msg->status_code==400 )
			{
				pWnd->ShowTestLogData+="<---------- 400\r\n";
			}
			else
			{
				AfxMessageBox("alarm other error",MB_OK|MB_ICONERROR);
			}
			//delete Alarmtemp;
		}
		else if (strcmp(m_SipMsg.msg->call_id->host,pWnd->TimeSetID.Host)==0 && 
			strcmp(m_SipMsg.msg->call_id->number,pWnd->TimeSetID.Num)==0 )
		{		
			// receive node message
			if ( !SipVerify(pWnd->m_InfoServer,pWnd->m_InfoClient,m_SipMsg.msg,1))
			{
				AfxMessageBox("Node Send From or To is error",MB_OK|MB_ICONERROR);
				delete XmlMessage;
				return 0;
			}
			if (m_SipMsg.msg->from->gen_params.nb_elt==0 )
			{
				AfxMessageBox("from variable must include tag",MB_OK|MB_ICONEXCLAMATION);
				delete XmlMessage;
				return 0;
			}
			osip_uri_param_t *h;
			osip_uri_param_init(&h);
			osip_from_get_tag(m_SipMsg.msg->from,&h);
			char Tag[10];
			strcpy(Tag,h->gvalue);
			osip_uri_param_free(h);
			if (strcmp(Tag,pWnd->TimeSetID.Tag)==0)
			{
				m_Type=TimeGet;	
			}
			else
			{
				AfxMessageBox("Tag is error",MB_OK|MB_ICONERROR);
				delete XmlMessage;
				return 0;
			}		
		}
	}
	switch ( m_Type )
	{
	case Register:
		{	
			cseq=m_SipMsg.msg->cseq;
			if ( m_SipMsg.msg->status_code==200 )
			{
				pWnd->ShowRecvData("\t\t-----注册成功-----\r\n");
				pWnd->ShowTestLogData += "<------------ 200 OK\r\n";
				//注册成功开启保活
				pWnd->bKeepAlive = TRUE;
				//osip_header_t *timeIntervalTemp = NULL;
				//osip_message_get_expires(m_SipMsg.msg, 0, &timeIntervalTemp);
				//char * expiresName = timeIntervalTemp->hname;
				//int timeInterval = atoi(timeIntervalTemp->hvalue);
				int timeInterval = atoi(Common::EXPIRES_VALUE) / 5 * 1000;
				pWnd->SetTimer(1, timeInterval, NULL);//成功后需要开启心跳信息保活,定时标志为1

				char *dst=new char[XMLSIZE];				
				char *dstNodeMsg=new char[MAXBUFSIZE];

				//根据测试文档要求，注册成功后需产生设备节点信息，然后发送给所有目的联网单元
				XmlNodeCreate(&dst);
				SipNodeXmlMsg(&dstNodeMsg,pWnd->m_InfoServer,pWnd->m_InfoClient,dst,m_SipMsg.msg);				
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstNodeMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				pWnd->ShowSendData(dstNodeMsg);

				Common::DEVICECATALOG_COUNT = 2;//第一次发送设备目录结构
				delete dst;					
				delete dstNodeMsg;				
				//update log
				pWnd->ShowTestLogData+="NOTIFY---------->\r\n";	
				pWnd->EnableWindow(IDC_BTN_RESULT,TRUE);	
				pWnd->m_Alarm.GetDlgItem(IDC_BTN_TIMESET)->EnableWindow(TRUE);	
			}
			/*else if (m_SipMsg.msg->status_code==600)
			{
				pWnd->ShowRecvData("\t\t-----注册信息超时,请重新注册-----\r\n");
				pWnd->bKeepAlive=FALSE;
				AfxMessageBox("心跳信息注册超时!");
				pWnd->KillTimer(3);
			}*/
			else if(m_SipMsg.msg->status_code==400)
			{	
				pWnd->ShowRecvData("\t\t-----注册失败或超时----\r\n");
				pWnd->ShowTestLogData+="<--------  400\r\n";
				pWnd->bKeepAlive=FALSE;
				pWnd->KillTimer(3);	
				pWnd->EnableWindow(IDC_BTN_SIP_REGISTER,TRUE);
				pWnd->EnableWindow(IDC_BTN_RESULT,FALSE);							
			}
			else if(m_SipMsg.msg->status_code==401)
			{	
				pWnd->ShowRecvData("\t\t-----注册失败(没有携带权签信息)----\r\n");
				pWnd->ShowTestLogData+="<--------  401\r\n";
// 				pWnd->bKeepAlive=FALSE;
// 				pWnd->KillTimer(3);	
// 				pWnd->EnableWindow(IDC_BTN_SIP_REGISTER,TRUE);
// 				pWnd->EnableWindow(IDC_BTN_RESULT,FALSE);
				string strbuf=buffer;
				int index=strbuf.find("realm");
				if (index==string::npos)
				{
					AfxMessageBox("缺少realm信息！",MB_OK|MB_ICONERROR);
					return 0;
				}
				int index1=strbuf.find('"',index);
				int index2=strbuf.find('"',index1+1);
				g_authInfo.realm=strbuf.substr(index1+1,index2-index1-1);

				index=strbuf.find("nonce");
				if (index==string::npos)
				{
					AfxMessageBox("缺少nonce信息！",MB_OK|MB_ICONERROR);
					return 0;
				}
				index1=strbuf.find('"',index);
				index2=strbuf.find('"',index1+1);
				g_authInfo.nonce=strbuf.substr(index1+1,index2-index1-1);

				index=strbuf.find("opaque");
				if (index==string::npos)
				{
					AfxMessageBox("缺少opaque信息！",MB_OK|MB_ICONERROR);
					return 0;
				}
				index1=strbuf.find('"',index);
				index2=strbuf.find('"',index1+1);
				g_authInfo.opaque=strbuf.substr(index1+1,index2-index1-1);

// 				index=strbuf.find("qop");
// 				if (index==string::npos)
// 				{
// 					AfxMessageBox("缺少qop信息！",MB_OK|MB_ICONERROR);
// 					return 0;
// 				}
// 				index1=strbuf.find('"',index);
// 				index2=strbuf.find('"',index1+1);
// 				g_authInfo.qop=strbuf.substr(index1+1,index2-index1-1);

				char *data=new char[MAXBUFSIZE];
				memset(data,0,MAXBUFSIZE);
				SipRegisterWithAuthCreate(&data,pWnd->m_InfoServer,pWnd->m_InfoClient,m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,data);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				pWnd->ShowTestLogTitle="Register Test";
				//update log	
				pWnd->ShowTestLogData+="REGISTER ------->  \r\n";
				//pWnd->SetTimer(3,5000,NULL);
			}
			else
			{
				//receive other message
				delete XmlMessage;
				return 1;
			}
		}
		break;
	case NodeType:
		{
			if (m_SipMsg.msg->status_code==200)
			{
				pWnd->ShowRecvData("\t\t-----设备节点信息发送成功-----\r\n");
				pWnd->ShowTestLogData += "<--------- 200 OK\r\n";

				char *dst = new char[XMLSIZE];
				char *dstNodeMsg = new char[MAXBUFSIZE];
				if (Common::DEVICECATALOG_COUNT == 2)//第二次推送：编码器下的模拟相机信息技术
				{
					XmlNodeCreate1(&dst);
					SipNodeXmlMsg(&dstNodeMsg,pWnd->m_InfoServer,pWnd->m_InfoClient,dst,m_SipMsg.msg);				
					UA_Msg uac_sendtemp;
					strcpy(uac_sendtemp.data,dstNodeMsg);
					EnterCriticalSection(&g_uac);
					uac_sendqueue.push(uac_sendtemp);
					LeaveCriticalSection(&g_uac);

					Common::DEVICECATALOG_COUNT = 3;
					delete dst;					
					delete dstNodeMsg;
				}	
				else if (Common::DEVICECATALOG_COUNT == 3)//第三次推送：DVR下所连接的模拟相机信息技术
				{
					XmlNodeCreate2(&dst);	
					SipNodeXmlMsg(&dstNodeMsg, pWnd->m_InfoServer, pWnd->m_InfoClient, dst, m_SipMsg.msg);
					UA_Msg uac_sendtemp;
					strcpy(uac_sendtemp.data, dstNodeMsg);
					EnterCriticalSection(&g_uac);
					uac_sendqueue.push(uac_sendtemp);
					LeaveCriticalSection(&g_uac);

					Common::DEVICECATALOG_COUNT = 1;
					delete dst;
					delete dstNodeMsg;
				}
			} 
			else if(m_SipMsg.msg->status_code==400)
			{
				pWnd->ShowRecvData("\t\t-----设备节点信息发送失败-----\r\n");
				pWnd->ShowTestLogData+="<--------- 400\r\n";			
				pWnd->KillTimer(3);
			}
			else
			{
				//receive other message
				delete XmlMessage;
				return 1;
			}
		}
		break;
	case Invite:
		{
			pWnd->bACK=FALSE;
			pWnd->bBYE=FALSE;
			//analyse XML message
			osip_body_t *XMLbody;
			osip_body_init(&XMLbody);
			osip_message_get_body (m_SipMsg.msg, 0, &XMLbody);
			memset(XmlMessage,0,XMLSIZE);
			memcpy(XmlMessage,XMLbody->body,strlen(XMLbody->body));
			osip_body_free(XMLbody);
			//100 try
			char *tryDst=new char[MAXBUFSIZE];
			Sip100Try(&tryDst,m_SipMsg.msg);
			//pWnd->SendData(tryDst);
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,tryDst);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);
			//pWnd->ShowSendData(tryDst);
			delete tryDst;
			//update log
			pWnd->ShowTestLogData+="100 ---------> \r\n";
			//sleep time			
			char *dst=new char[XMLSIZE];
			char *dstInviteMsg=new char[MAXBUFSIZE];
			if( XmlInviteCreate(&dst,XmlMessage) )
			{
				SipInvite200Xml(&dstInviteMsg,m_SipMsg.msg,dst);
				//pWnd->SendData(dstInviteMsg);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstInviteMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dstInviteMsg);
				delete dst;		
				delete dstInviteMsg;			
				//update log
				pWnd->ShowTestLogData+="200 OK --------> \r\n";			
			}
			else
			{
				SipInvite400(&dstInviteMsg,m_SipMsg.msg);
				//pWnd->SendData(dstInviteMsg);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstInviteMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dstInviteMsg);
				delete dst;		
				delete dstInviteMsg;
				//update log
				pWnd->ShowTestLogData+="400 --------> \r\n";
			}			
		}
		break;
	case CANCEL:
		{
			pWnd->bACK=TRUE;
			pWnd->bBYE=TRUE;
			
			//sleep time			
			char *dst=new char[XMLSIZE];
			char *dstInviteMsg=new char[MAXBUFSIZE];
// 			if( XmlInviteCreate(&dst,XmlMessage) )
// 			{
// 				SipInvite200Xml(&dstInviteMsg,m_SipMsg.msg,dst);
// 				//pWnd->SendData(dstInviteMsg);	
// 				UA_Msg uac_sendtemp;
// 				strcpy(uac_sendtemp.data,dstInviteMsg);
// 				EnterCriticalSection(&g_uac);
// 				uac_sendqueue.push(uac_sendtemp);
// 				LeaveCriticalSection(&g_uac);
// 				//pWnd->ShowSendData(dstInviteMsg);
// 				delete dst;		
// 				delete dstInviteMsg;			
// 				//update log
// 				pWnd->ShowTestLogData+="200 OK --------> \r\n";			
// 			}
			//SipInvite200Xml(&dstInviteMsg,m_SipMsg.msg,"");
			SipCancel200Xml(&dstInviteMsg,m_SipMsg.msg);
			//pWnd->SendData(dstInviteMsg);	
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dstInviteMsg);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);
			//pWnd->ShowSendData(dstInviteMsg);
			delete dst;		
			delete dstInviteMsg;			
			//update log
			pWnd->ShowTestLogData+="200 OK --------> \r\n";		

		}
		break;
	case PTZ:
		{
			char *dst=new char[XMLSIZE];
			char *dstPTZMsg=new char[MAXBUFSIZE];
			if( XmlPTZCreate(&dst,XmlMessage) )
			{
				Sip200Xml(&dstPTZMsg,m_SipMsg.msg,dst);
				//pWnd->SendData(dstPTZMsg);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstPTZMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dstPTZMsg);
				delete dst;		
				delete dstPTZMsg;
				//update log
				pWnd->ShowTestLogData+="200  OK ------->\r\n";			
			}
			else
			{
				Sip400(&dstPTZMsg,m_SipMsg.msg);
				//pWnd->SendData(dstPTZMsg);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstPTZMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dstPTZMsg);
				delete dst;		
				delete dstPTZMsg;
				//update log
				pWnd->ShowTestLogData+="400  ------->\r\n";
			}
		}
		break;
	case PreBitSet:
		{					
			char *xml=new char[XMLSIZE];			
			//CreateXMLVideoQuery(&xml);
			if (endIndex>PresetInfoList.size()/4)
			{
				endIndex=PresetInfoList.size()/4;
			}
			if(endIndex-beginIndex<5)CreateXMLptzPreBitQuery_c(&xml,beginIndex,endIndex);
			else CreateXMLptzPreBitQuery_c(&xml,beginIndex,beginIndex+4);
			//char*xml=(LPSTR)(LPCTSTR)strTemp;	
			char *dstMsg=new char[MAXBUFSIZE];
			Sip200Xml(&dstMsg,m_SipMsg.msg,xml);
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dstMsg);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);
			//pWnd->ShowSendData(dstPTZMsg);		
			delete dstMsg;
			//update log
			pWnd->ShowTestLogData+="200  OK ------->\r\n";	
		}
		break;
	case HistoryQuery:
		{
			char *xml=new char[XMLSIZE];			
			//CreateXMLVideoQuery(&xml);
			if (endIndex*6>HistoryVideoList.size())
			{
				endIndex=HistoryVideoList.size()/6;
			}
			if(endIndex-beginIndex<5)CreateXMLVideoQuery_c(&xml,beginIndex,endIndex);
			else CreateXMLVideoQuery_c(&xml,beginIndex,beginIndex+4);
			char *dest=new char[MAXBUFSIZE];
			Sip200Xml(&dest,m_SipMsg.msg,xml);				
			//pWnd->SendData(dest);
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dest);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);		
			//pWnd->ShowSendData(dest);
			delete dest;
			delete xml;			
			//update log
			pWnd->ShowTestLogData+="200 OK ----------->\r\n";
		}
		break;
	case CatalogQuery:
		{
			string st=buffer;
			int index = st.find("<Address>",0);
			if (index==string::npos)
			{
				AfxMessageBox("目录查询，缺少Address字段！",MB_OK|MB_ICONERROR);
			}
			int index2=st.find("</Address>");
			if (index2==string::npos)
			{
				AfxMessageBox("目录查询，缺少Address字段！",MB_OK|MB_ICONERROR);
			}
			string strT=st.substr(index+9,index2-index-9);
			if (strT.compare("")==0)
			{
				AfxMessageBox("目录查询，Address字段为空！",MB_OK|MB_ICONERROR);
			}
			if (strT.compare("252000001199000001")==0)
			{
				char *xml=new char[XMLSIZE];			
				CreateXMLCatalogQuery(&xml);
				char *dest=new char[MAXBUFSIZE];
				Sip200Xml(&dest,m_SipMsg.msg,xml);				
				//pWnd->SendData(dest);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dest);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dest);
				delete dest;
				delete xml;
			}
			if (strT.compare("252000001199002001")==0)
			{
				char *xml=new char[XMLSIZE];
				CreateXMLCatalogQuery2(&xml);
				char *dest=new char[MAXBUFSIZE];
				Sip200Xml(&dest,m_SipMsg.msg,xml);
				//pWnd->SendData(dest);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dest);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dest);
				delete dest;
				delete xml;
			}
// 			char *xml=new char[XMLSIZE];			
// 			CreateXMLCatalogQuery(&xml);
// 			char *dest=new char[MAXBUFSIZE];
// 			Sip200Xml(&dest,m_SipMsg.msg,xml);				
// 			//pWnd->SendData(dest);
// 			UA_Msg uac_sendtemp;
// 			strcpy(uac_sendtemp.data,dest);
// 			EnterCriticalSection(&g_uac);
// 			uac_sendqueue.push(uac_sendtemp);
// 			LeaveCriticalSection(&g_uac);		
// 			//pWnd->ShowSendData(dest);
// 			delete dest;
// 			delete xml;			
			//update log
			pWnd->ShowTestLogData+="200 OK ----------->\r\n";
		}
		break;
	case DeviceInfQuery:
		{
			char *xml=new char[XMLSIZE];			
			CreateXMLDeviceInfQuery(&xml);
			char *dest=new char[MAXBUFSIZE];
			Sip200Xml(&dest,m_SipMsg.msg,xml);				
			//pWnd->SendData(dest);
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dest);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);		
			//pWnd->ShowSendData(dest);
			delete dest;
			delete xml;			
			//update log
			pWnd->ShowTestLogData+="200 OK ----------->\r\n";
		}
		break;
	case FlowQuery:
		{
			char *xml=new char[XMLSIZE];			
			CreateXMLFlowQuery(&xml);
			char *dest=new char[MAXBUFSIZE];
			Sip200Xml(&dest,m_SipMsg.msg,xml);				
			//pWnd->SendData(dest);
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dest);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);		
			//pWnd->ShowSendData(dest);
			delete dest;
			delete xml;			
			//update log
			pWnd->ShowTestLogData+="200 OK ----------->\r\n";
		}
		break;
	case HistoryPlay:
		{
			//create XML message		
			CString strTemp;
			strTemp="<?xml version=\"1.0\"?>\r\n";
			strTemp+="<Response>\r\n";
			//strTemp+="<QueryResponse>\r\n";
			strTemp+="<Variable>VODByRTSP</Variable>\r\n";
			strTemp+="<Result>0</Result>\r\n";
			strTemp+="<Bitrate>100</Bitrate>\r\n";
			//rtsp://192.168.1.7:8554/filename.264
			// rtsp://192.168.1.7:8554/<filename>
			strTemp+="<Playurl>rtsp://"+pWnd->m_InfoClient.IP+":"+/*pWnd->TCP_Port*/"8554/filename.264"+"</Playurl>\r\n";
			//strTemp+="</QueryResponse>\r\n";
			strTemp+="</Response>\r\n";
			char*xml=(LPSTR)(LPCTSTR)strTemp;
			char *dst=new char[MAXBUFSIZE];
			Sip200Xml(&dst,m_SipMsg.msg,xml);			
			//pWnd->SendData(dst);	
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dst);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);
			//pWnd->ShowSendData(dst);
			delete dst;		
			//update log
			pWnd->ShowTestLogData+="200 OK --------->\r\n";
		}
		break;
	case EncoderSet:
		{
			char *dst=new char[XMLSIZE];
			char *dstEncoderSetMsg=new char[MAXBUFSIZE];
			if( XmlEncoderSetCreate(&dst,XmlMessage) )
			{
				Sip200Xml(&dstEncoderSetMsg,m_SipMsg.msg,dst);
				//pWnd->SendData(dstEncoderSetMsg);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstEncoderSetMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dstEncoderSetMsg);
				delete dst;		
				delete dstEncoderSetMsg;
				//update log
				pWnd->ShowTestLogData+="200  OK -------->\r\n";	
			}
			else
			{
				Sip400(&dstEncoderSetMsg,m_SipMsg.msg);
				//pWnd->SendData(dstEncoderSetMsg);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstEncoderSetMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dstEncoderSetMsg);
				//update log
				pWnd->ShowTestLogData+="400  -------->\r\n";	
				delete dst;		
				delete dstEncoderSetMsg;
			}
		}
		break;
	case TimeGet:
		{
			if (m_SipMsg.msg->status_code==200)
			{
				//receive 200 ok message			
				pWnd->ShowRecvData("\t\t-----时间较正成功-----\r\n");
				//update log			
				pWnd->ShowTestLogData+="<----------200  OK \r\n";
			}
			else if (m_SipMsg.msg->status_code==400)
			{
				//receive 400 ok message
				pWnd->ShowRecvData("\t----时间较正失败----\r\n");	
				//update log				
				pWnd->ShowTestLogData+=" <---------  400\r\n";
			}
			else
			{
				//receive other message
				delete XmlMessage;
				return 1;
			}
		}
		break;
	case TimeSet:
		{
			CString strTemp;
			strTemp="<?xml version=\"1.0\"?>\r\n";
			strTemp+="<Response>\r\n";
			strTemp+="<ControlResponse>\r\n";
			strTemp+="<Variable>TimeSet</Variable>\r\n";
			strTemp+="<Result>0</Result>\r\n";
			strTemp+="<Privilege>0100100001</Privilege>\r\n";				
			strTemp+="</ControlResponse>\r\n";
			strTemp+="</Response>\r\n";
			char*xml=(LPSTR)(LPCTSTR)strTemp;	
			char *dstMsg=new char[MAXBUFSIZE];
			Sip200Xml(&dstMsg,m_SipMsg.msg,xml);
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dstMsg);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);
			//pWnd->ShowSendData(dstPTZMsg);		
			delete dstMsg;
			//update log
			pWnd->ShowTestLogData+="200  OK ------->\r\n";	
		}
		break;
	case Alarm:
		{
			//analyse XML message
			osip_body_t *XMLbody;
			osip_body_init(&XMLbody);
			osip_message_get_body (m_SipMsg.msg, 0, &XMLbody);
			memset(XmlMessage,0,XMLSIZE);
			memcpy(XmlMessage,XMLbody->body,strlen(XMLbody->body));
			osip_body_free(XMLbody);
			char *dst=new char[XMLSIZE];
			char *dstAlarmMsg=new char[MAXBUFSIZE];
			if( XmlAlarmCreate(&dst,XmlMessage) )
			{
				Sip200Xml(&dstAlarmMsg,m_SipMsg.msg,dst);
				//pWnd->SendData(dstAlarmMsg);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstAlarmMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dstAlarmMsg);
				delete dst;		
				delete dstAlarmMsg;				
				//update log
				pWnd->ShowTestLogData+="200  OK ---------->\r\n";					
				if ( strcmp(m_SipMsg.msg->call_id->host,"")==0 )
				{	
					
					strcpy(pWnd->AlarmCallID,m_SipMsg.msg->call_id->number);
				}
				else
				{
					char *dest=NULL;
					osip_call_id_to_str(m_SipMsg.msg->call_id,&dest);
					strcpy(pWnd->AlarmCallID,dest);
					osip_free(dest);
				}				
				//sleep time				
				char *alarmnotify=new char[MAXBUFSIZE];
				SipAlarmSubscribeNotify(&alarmnotify,pWnd->m_InfoServer,pWnd->m_InfoClient,m_SipMsg.msg);
				//pWnd->SendData(alarmnotify);	
				UA_Msg uac_sendtemp1;
				strcpy(uac_sendtemp1.data,alarmnotify);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp1);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(alarmnotify);
				delete alarmnotify;	
				pWnd->balarmsubscribe=FALSE;
				pWnd->ShowTestLogData+="NOTIFY ---------->\r\n";					
			}
			else
			{
				Sip400(&dstAlarmMsg,m_SipMsg.msg);
				//pWnd->SendData(dstAlarmMsg);	
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstAlarmMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//pWnd->ShowSendData(dstAlarmMsg);
				delete dst;		
				delete dstAlarmMsg;
				//update log
				pWnd->ShowTestLogData+="400  ---------->\r\n";
			}
		}
		break;
	default:
		break;
	}
	delete XmlMessage;
	XmlMessage=NULL;
	return 0;
}

void CSipMsgProcess::SipInvite400(char **dst,osip_message_t *srcmsg)
{
	//生成400 报文
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	osip_message_set_version(Sip200->m_SipMsg.msg,"SIP/2.0");
	osip_message_set_status_code(Sip200->m_SipMsg.msg,400);
	osip_message_set_reason_phrase(Sip200->m_SipMsg.msg,"");
	//osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);	
	if ( strcmp(srcmsg->call_id->host,"")==0 )
	{	
		osip_call_id_set_number(Sip200->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip200->m_SipMsg.callid,&dest);
		osip_message_set_call_id(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);
	}
	else
		osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	osip_from_clone(srcmsg->from,&Sip200->m_SipMsg.msg->from);	
	osip_to_clone(srcmsg->to,&Sip200->m_SipMsg.msg->to);	
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	if (srcmsg->to->gen_params.nb_elt==0 )
	{
		osip_to_set_tag(Sip200->m_SipMsg.msg->to,pWnd->invite100tag);
	}	
	osip_cseq_clone(srcmsg->cseq,&Sip200->m_SipMsg.msg->cseq);		
	osip_message_set_contact(Sip200->m_SipMsg.msg,pWnd->contact);
	osip_free(dest);
	//copy via
	osip_message_get_via(srcmsg,0,&Sip200->m_SipMsg.via);
	osip_via_to_str(Sip200->m_SipMsg.via,&dest);
	osip_message_set_via(Sip200->m_SipMsg.msg,dest);
	//CSipMsgProcess *Sip200=new CSipMsgProcess;
	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
	CString st0;
	if (1==i)
	{

		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(Sip200->m_SipMsg.msg,dest);
		st0=dest;
		st0="Via: "+st0+"\r\n";		
	}
	else
	{
		st0="";
	}
	osip_free(dest);	
	osip_message_to_str(Sip200->m_SipMsg.msg,&dest,&len);
	memset(*dst,0,MAXBUFSIZE);
	memcpy(*dst,dest,len);
	osip_free(dest);
}

void CSipMsgProcess::Sip200OK(char **dst,osip_message_t *srcmsg)
{
	char FromTag[10];
	int RandData;
	RandData=rand();	
	char str[8];
	itoa(RandData,str,10);
	strcpy(FromTag,str);
	//生成200 OK报文
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	osip_message_set_version(Sip200->m_SipMsg.msg,"SIP/2.0");
	osip_message_set_status_code(Sip200->m_SipMsg.msg,200);
	osip_message_set_reason_phrase(Sip200->m_SipMsg.msg,"OK");
	//osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);	
	if ( strcmp(srcmsg->call_id->host,"")==0 )
	{	
		osip_call_id_set_number(Sip200->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip200->m_SipMsg.callid,&dest);
		osip_message_set_call_id(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);
	}
	else
	osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	osip_from_clone(srcmsg->from,&Sip200->m_SipMsg.msg->from);	
	osip_to_clone(srcmsg->to,&Sip200->m_SipMsg.msg->to);	
	if (srcmsg->to->gen_params.nb_elt==0 )
	{
		osip_to_set_tag(Sip200->m_SipMsg.msg->to,FromTag);
	}	
	osip_cseq_clone(srcmsg->cseq,&Sip200->m_SipMsg.msg->cseq);
	//copy contact
	/*osip_message_get_contact(srcmsg,0,&Sip200->m_SipMsg.contact);
	osip_contact_to_str(Sip200->m_SipMsg.contact,&dest);
	osip_message_set_contact(Sip200->m_SipMsg.msg,dest);*/
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	osip_message_set_contact(Sip200->m_SipMsg.msg,pWnd->contact);
	osip_free(dest);
	//copy via
	osip_message_get_via(srcmsg,0,&Sip200->m_SipMsg.via);
	osip_via_to_str(Sip200->m_SipMsg.via,&dest);
	osip_message_set_via(Sip200->m_SipMsg.msg,dest);
	//CSipMsgProcess *Sip200=new CSipMsgProcess;
	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
	CString st0;
	if (1==i)
	{

		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(Sip200->m_SipMsg.msg,dest);
		st0=dest;
		st0="Via: "+st0+"\r\n";		
	}
	else
	{
		st0="";
	}
	osip_free(dest);	
	osip_message_to_str(Sip200->m_SipMsg.msg,&dest,&len);
	memset(*dst,0,MAXBUFSIZE);
	memcpy(*dst,dest,len);
	osip_free(dest);
}

void CSipMsgProcess::Sip100Try(char **dst,osip_message_t *srcmsg)
{
	char FromTag[10];
	int RandData;	
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(FromTag,str);
	//生成100 try报文
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip=new CSipMsgProcess;
	osip_message_set_version(Sip->m_SipMsg.msg,"SIP/2.0");
	osip_message_set_status_code(Sip->m_SipMsg.msg,100);
	osip_message_set_reason_phrase(Sip->m_SipMsg.msg,"");
	//osip_call_id_clone(srcmsg->call_id,&Sip->m_SipMsg.msg->call_id);
	if ( strcmp(srcmsg->call_id->host,"")==0 )
	{	
		char *p=NULL;
		osip_call_id_set_number(Sip->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip->m_SipMsg.callid,&p);
		osip_message_set_call_id(Sip->m_SipMsg.msg,p);
		osip_free(p);
	}
	else
		osip_call_id_clone(srcmsg->call_id,&Sip->m_SipMsg.msg->call_id);	
	osip_from_clone(srcmsg->from,&Sip->m_SipMsg.msg->from);
	osip_to_clone(srcmsg->to,&Sip->m_SipMsg.msg->to);	
	osip_to_set_tag(Sip->m_SipMsg.msg->to,FromTag);	
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	strcpy(pWnd->invite100tag,FromTag);
	osip_cseq_clone(srcmsg->cseq,&Sip->m_SipMsg.msg->cseq);
	//copy contact
	/*osip_message_get_contact(srcmsg,0,&Sip->m_SipMsg.contact);
	osip_contact_to_str(Sip->m_SipMsg.contact,&dest);
	osip_message_set_contact(Sip->m_SipMsg.msg,dest);*/	
	osip_message_set_contact(Sip->m_SipMsg.msg,pWnd->contact);
	osip_free(dest);
	//copy via
	osip_message_get_via(srcmsg,0,&Sip->m_SipMsg.via);
	osip_via_to_str(Sip->m_SipMsg.via,&dest);
	osip_message_set_via(Sip->m_SipMsg.msg,dest);
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
	CString st0;
	if (1==i)
	{

		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(Sip->m_SipMsg.msg,dest);
		st0=dest;
		st0="Via: "+st0+"\r\n";		
	}
	else
	{
		st0="";
	}
	osip_free(dest);
	osip_message_set_max_forwards(Sip->m_SipMsg.msg,"70");
	osip_message_to_str(Sip->m_SipMsg.msg,&dest,&len);
	memset(*dst,0,MAXBUFSIZE);
	memcpy(*dst,dest,len);
	osip_free(dest);
}

void CSipMsgProcess::Sip400(char **dst,osip_message_t *srcmsg)
{
	char FromTag[10];
	int RandData;
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(FromTag,str);
	//生成400 报文
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	osip_message_set_version(Sip200->m_SipMsg.msg,"SIP/2.0");
	osip_message_set_status_code(Sip200->m_SipMsg.msg,400);	
	osip_message_set_reason_phrase(Sip200->m_SipMsg.msg,"");
	//osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	if ( strcmp(srcmsg->call_id->host,"")==0 )
	{	
		osip_call_id_set_number(Sip200->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip200->m_SipMsg.callid,&dest);
		osip_message_set_call_id(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);
	}
	else
		osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	osip_from_clone(srcmsg->from,&Sip200->m_SipMsg.msg->from);
	osip_to_clone(srcmsg->to,&Sip200->m_SipMsg.msg->to);
	if (srcmsg->to->gen_params.nb_elt==0 )
	{
		osip_to_set_tag(Sip200->m_SipMsg.msg->to,FromTag);
	}
	osip_cseq_clone(srcmsg->cseq,&Sip200->m_SipMsg.msg->cseq);
	//copy contact
	/*osip_message_get_contact(srcmsg,0,&Sip200->m_SipMsg.contact);
	osip_contact_to_str(Sip200->m_SipMsg.contact,&dest);
	osip_message_set_contact(Sip200->m_SipMsg.msg,dest);*/
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	osip_message_set_contact(Sip200->m_SipMsg.msg,pWnd->contact);
	osip_free(dest);
	//copy via
	osip_message_get_via(srcmsg,0,&Sip200->m_SipMsg.via);
	//CSipMsgProcess *Sip200=new CSipMsgProcess;
	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
	CString st0;
	if (1==i)
	{

		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(Sip200->m_SipMsg.msg,dest);
		st0=dest;
		st0="Via: "+st0+"\r\n";		
	}
	else
	{
		st0="";
	}
	osip_via_to_str(Sip200->m_SipMsg.via,&dest);
	osip_message_set_via(Sip200->m_SipMsg.msg,dest);
	osip_free(dest);	
	osip_message_to_str(Sip200->m_SipMsg.msg,&dest,&len);
	memset(*dst,0,MAXBUFSIZE);
	memcpy(*dst,dest,len);
	osip_free(dest);
}

void CSipMsgProcess::DOKeepAliveMsg(char **dst,InfoServer m_InfoServer,InfoClient m_InfoClient,char *Xml)
{
	char FromTag[10];
	char CallID[10];
	//远程配置信息
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//本地配置信息
	char *srcCode=(LPSTR)(LPCTSTR)m_InfoClient.UserAddress;
	char *srcUserName=(LPSTR)(LPCTSTR)m_InfoClient.UserName;
	char *srcIP=(LPSTR)(LPCTSTR)m_InfoClient.IP;
	char *srcPort=(LPSTR)(LPCTSTR)m_InfoClient.Port;

	int RandData;
	srand((unsigned int)time(0));
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(FromTag,str);
	RandData=rand();
	itoa(RandData,str,10);
	strcpy(CallID,str);

	char *dest;
	CSipMsgProcess *SipHeader=new CSipMsgProcess;
	////////////////////////
	osip_uri_set_host(SipHeader->m_SipMsg.uriServer,dstIP);
	osip_uri_set_scheme(SipHeader->m_SipMsg.uriServer,"sip");
	osip_uri_set_username(SipHeader->m_SipMsg.uriServer,dstCode);
	osip_uri_set_port(SipHeader->m_SipMsg.uriServer,dstPort);	

	osip_uri_set_host(SipHeader->m_SipMsg.uriClient,srcIP);
	osip_uri_set_scheme(SipHeader->m_SipMsg.uriClient,"sip");
	osip_uri_set_username(SipHeader->m_SipMsg.uriClient,srcCode);
	osip_uri_set_port(SipHeader->m_SipMsg.uriClient,srcPort);

	osip_via_set_version(SipHeader->m_SipMsg.via,"2.0");
	osip_via_set_protocol(SipHeader->m_SipMsg.via,"UDP");
	osip_via_set_port(SipHeader->m_SipMsg.via,srcPort);
	//osip_via_set_branch(via,"123456789");//随机数
// 	RandData=rand();	
// 	char sdtr[10];	
// 	char branch[20];
// 	itoa(RandData,sdtr,16);
// 	strcpy(branch,"z9hG4bK--");
// 	strcat(branch,sdtr);
// 	osip_via_set_branch(SipHeader->m_SipMsg.via,branch);//随机数
	//osip_via_set_branch(SipHeader->m_SipMsg.via,"z9hG4bK--22bd9222");//随机数
	osip_via_set_host(SipHeader->m_SipMsg.via,srcIP);

	osip_call_id_set_host(SipHeader->m_SipMsg.callid,srcIP);
	osip_call_id_set_number(SipHeader->m_SipMsg.callid,CallID);//随机数

	//osip_from_set_displayname(SipHeader->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipHeader->m_SipMsg.from,FromTag);//随机数
	osip_from_set_url(SipHeader->m_SipMsg.from,SipHeader->m_SipMsg.uriClient);
	//保留本注册的消息的CallID信息		
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	memset(pWnd->KeepAliveID.Host,0,HOSTSIZE);
	memset(pWnd->KeepAliveID.Num,0,NUMSIZE);
	memset(pWnd->KeepAliveID.Tag,0,NUMSIZE);
	strcpy(pWnd->KeepAliveID.Host,srcIP);
	strcpy(pWnd->KeepAliveID.Num,CallID);
	strcpy(pWnd->KeepAliveID.Tag,FromTag);
	//osip_to_set_displayname(SipHeader->m_SipMsg.to,dstUserName);	
	osip_to_set_url(SipHeader->m_SipMsg.to,SipHeader->m_SipMsg.uriServer);

	osip_cseq_set_method(SipHeader->m_SipMsg.cseq,"DO");
	pWnd->nKeepCseq++;	
	char str1[20];		
	itoa(pWnd->nKeepCseq,str1,10);
	osip_cseq_set_number(SipHeader->m_SipMsg.cseq,str1);

	osip_message_set_uri(SipHeader->m_SipMsg.msg,SipHeader->m_SipMsg.uriServer);
	osip_message_set_method(SipHeader->m_SipMsg.msg,"DO");

	osip_contact_set_url(SipHeader->m_SipMsg.contact,SipHeader->m_SipMsg.uriClient);
	osip_contact_set_displayname(SipHeader->m_SipMsg.contact,srcUserName);
	osip_message_set_max_forwards(SipHeader->m_SipMsg.msg,"70");

	osip_to_to_str(SipHeader->m_SipMsg.to,&dest);
	osip_message_set_to(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_call_id_to_str(SipHeader->m_SipMsg.callid,&dest);
	osip_message_set_call_id(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_from_to_str(SipHeader->m_SipMsg.from,&dest);
	osip_message_set_from(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_contact_to_str(SipHeader->m_SipMsg.contact,&dest);
	osip_message_set_contact(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_cseq_to_str(SipHeader->m_SipMsg.cseq,&dest);
	osip_message_set_cseq(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_via_to_str(SipHeader->m_SipMsg.via,&dest);
	osip_message_set_via(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);	
	osip_message_set_content_type(SipHeader->m_SipMsg.msg,"Application/DDCP");
	osip_message_set_body(SipHeader->m_SipMsg.msg,Xml,strlen(Xml));
	size_t length;	
	osip_message_to_str(SipHeader->m_SipMsg.msg,&dest,&length);	
	strcpy(*dst,dest);
	osip_free(dest);
}

void CSipMsgProcess::SipInvite200Xml(char **dstBuf,osip_message_t *srcmsg,CString Xml)
{
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	osip_message_set_version(Sip200->m_SipMsg.msg,"SIP/2.0");
	osip_message_set_status_code(Sip200->m_SipMsg.msg,200);
	osip_message_set_reason_phrase(Sip200->m_SipMsg.msg,"OK");	
	if ( strcmp(srcmsg->call_id->host,"")==0 )
	{	
		osip_call_id_set_number(Sip200->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip200->m_SipMsg.callid,&dest);
		osip_message_set_call_id(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);
	}
	else
		osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	osip_from_clone(srcmsg->from,&Sip200->m_SipMsg.msg->from);
	osip_to_clone(srcmsg->to,&Sip200->m_SipMsg.msg->to);
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	if (srcmsg->to->gen_params.nb_elt==0 )
	{
		osip_to_set_tag(Sip200->m_SipMsg.msg->to,pWnd->invite100tag);		
	}	
	osip_cseq_clone(srcmsg->cseq,&Sip200->m_SipMsg.msg->cseq);
	osip_message_set_contact(Sip200->m_SipMsg.msg,pWnd->contact);
	//osip_free(dest);
	osip_message_get_via(srcmsg,0,&Sip200->m_SipMsg.via);
	osip_via_to_str(Sip200->m_SipMsg.via,&dest);	
	osip_message_set_via(Sip200->m_SipMsg.msg,dest);
	//CSipMsgProcess *Sip200=new CSipMsgProcess;
	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
	CString st0;
	if (1==i)
	{

		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(Sip200->m_SipMsg.msg,dest);
		st0=dest;
		st0="Via: "+st0+"\r\n";		
	}
	else
	{
		st0="";
	}
	osip_free(dest);
	//load XML message in to sip message
	osip_message_set_content_type(Sip200->m_SipMsg.msg,"Application/DDCP");
	char *xml=(LPSTR)(LPCTSTR)Xml;
	osip_message_set_body(Sip200->m_SipMsg.msg,xml,strlen(xml));		
	osip_message_to_str(Sip200->m_SipMsg.msg,&dest,&len);
	memset(*dstBuf,0,MAXBUFSIZE);
	if(dest!=NULL)memcpy(*dstBuf,dest,len);
	osip_free(dest);
}

void CSipMsgProcess::SipCancel200Xml(char **dstBuf,osip_message_t *srcmsg)
{
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	osip_message_set_version(Sip200->m_SipMsg.msg,"SIP/2.0");
	osip_message_set_status_code(Sip200->m_SipMsg.msg,200);
	osip_message_set_reason_phrase(Sip200->m_SipMsg.msg,"OK");	
	if ( strcmp(srcmsg->call_id->host,"")==0 )
	{	
		osip_call_id_set_number(Sip200->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip200->m_SipMsg.callid,&dest);
		osip_message_set_call_id(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);
	}
	else
		osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	osip_from_clone(srcmsg->from,&Sip200->m_SipMsg.msg->from);
	osip_to_clone(srcmsg->to,&Sip200->m_SipMsg.msg->to);
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	if (srcmsg->to->gen_params.nb_elt==0 )
	{
		osip_to_set_tag(Sip200->m_SipMsg.msg->to,pWnd->invite100tag);		
	}	
	osip_cseq_clone(srcmsg->cseq,&Sip200->m_SipMsg.msg->cseq);
	osip_message_set_contact(Sip200->m_SipMsg.msg,pWnd->contact);
	//osip_free(dest);
	osip_message_get_via(srcmsg,0,&Sip200->m_SipMsg.via);
	osip_via_to_str(Sip200->m_SipMsg.via,&dest);	
	osip_message_set_via(Sip200->m_SipMsg.msg,dest);
	//CSipMsgProcess *Sip200=new CSipMsgProcess;
	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
	CString st0;
	if (1==i)
	{

		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(Sip200->m_SipMsg.msg,dest);
		st0=dest;
		st0="Via: "+st0+"\r\n";		
	}
	else
	{
		st0="";
	}
	osip_free(dest);
	//load XML message in to sip message
	osip_message_set_content_type(Sip200->m_SipMsg.msg,"Application/DDCP");
// 	char *xml=(LPSTR)(LPCTSTR)Xml;
// 	osip_message_set_body(Sip200->m_SipMsg.msg,xml,strlen(xml));		
	osip_message_to_str(Sip200->m_SipMsg.msg,&dest,&len);
	memset(*dstBuf,0,MAXBUFSIZE);
	memcpy(*dstBuf,dest,len);
	osip_free(dest);
}

//带SIP头和XML文档消息体的完整消息
void CSipMsgProcess::Sip200Xml(char **dstBuf,osip_message_t *srcmsg,CString Xml)
{	
	char FromTag[10];
	int RandData;
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(FromTag,str);
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	osip_message_set_version(Sip200->m_SipMsg.msg,"SIP/2.0");
	osip_message_set_status_code(Sip200->m_SipMsg.msg,200);
	osip_message_set_reason_phrase(Sip200->m_SipMsg.msg,"OK");
	//osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	if ( strcmp(srcmsg->call_id->host,"")==0 )
	{	
		osip_call_id_set_number(Sip200->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip200->m_SipMsg.callid,&dest);
		osip_message_set_call_id(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);
	}
	else
		osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	osip_from_clone(srcmsg->from,&Sip200->m_SipMsg.msg->from);
	osip_to_clone(srcmsg->to,&Sip200->m_SipMsg.msg->to);
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	if (srcmsg->to->gen_params.nb_elt==0 )
	{
		osip_to_set_tag(Sip200->m_SipMsg.msg->to,FromTag);
		if (pWnd->balarmsubscribe)
		{
			strcpy(pWnd->alarmTag,FromTag);
		}		
	}	
	osip_cseq_clone(srcmsg->cseq,&Sip200->m_SipMsg.msg->cseq);
	//osip_message_get_contact(srcmsg,0,&Sip200->m_SipMsg.contact);
	//osip_contact_to_str(Sip200->m_SipMsg.contact,&dest);	
	osip_message_set_contact(Sip200->m_SipMsg.msg,pWnd->contact);
	//osip_free(dest);
	osip_message_get_via(srcmsg,0,&Sip200->m_SipMsg.via);
	osip_via_to_str(Sip200->m_SipMsg.via,&dest);	
	osip_message_set_via(Sip200->m_SipMsg.msg,dest);
	//CSipMsgProcess *Sip200=new CSipMsgProcess;
	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
	CString st0;
	if (1==i)
	{

		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(Sip200->m_SipMsg.msg,dest);
		st0=dest;
		st0="Via: "+st0+"\r\n";		
	}
	else
	{
		st0="";
	}
	osip_free(dest);
	//load XML message in to sip message
	osip_message_set_content_type(Sip200->m_SipMsg.msg,"Application/DDCP");
	char *xml=(LPSTR)(LPCTSTR)Xml;
	osip_message_set_body(Sip200->m_SipMsg.msg,xml,strlen(xml));		
	osip_message_to_str(Sip200->m_SipMsg.msg,&dest,&len);

	string st="Expires:90\r\n";
	string strtemp=dest;
	int index=strtemp.find("Content-Type");
	if (index==string::npos)
	{
		AfxMessageBox("sip200缺少，Content-Type");
	}
	strtemp.insert(index,st);
	strcpy(*dstBuf,strtemp.c_str());

	osip_free(dest);
}

BOOL CSipMsgProcess::XmlInviteCreate(char** strInviteXml,char *srcXml)
{
	string strTemp(srcXml);		
	string Format;
	string Video;
	string Audio;
	string MaxBitrate;
	string TransmitMode;
	string Protocol;
	string Multicast;
	string::size_type VariableStart;	
	string::size_type VariableEnd;	

	if( (VariableStart=strTemp.find("<Format>",0)) ==string::npos)
	{
		AfxMessageBox("实时流请求缺少Format字段");
		return FALSE;	
	}
							
	if ( (VariableEnd=strTemp.find("</Format>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("实时流请求缺少Format字段");
		return FALSE;	
	}	
	Format=strTemp.substr(VariableStart+8,VariableEnd-VariableStart-8);
	if( (VariableStart=strTemp.find("<Video>",0)) ==string::npos)			
	{
		AfxMessageBox("实时流请求缺少Video字段");
		return FALSE;	
	}					
	if ( (VariableEnd=strTemp.find("</Video>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("实时流请求缺少Video字段");
		return FALSE;	
	}				
	Video=strTemp.substr(VariableStart+7,VariableEnd-VariableStart-7);
	if( (VariableStart=strTemp.find("<Audio>",0)) ==string::npos)			
	{
		AfxMessageBox("实时流请求缺少Audio字段");
		return FALSE;	
	}								
	if ( (VariableEnd=strTemp.find("</Audio>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("实时流请求缺少Audio字段");
		return FALSE;	
	}			
	Audio=strTemp.substr(VariableStart+7,VariableEnd-VariableStart-7);
	if( (VariableStart=strTemp.find("<MaxBitrate>",0)) ==string::npos)			
	{
		AfxMessageBox("实时流请求缺少MaxBitrate字段");
		return FALSE;	
	}							
	if ( (VariableEnd=strTemp.find("</MaxBitrate>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("实时流请求缺少MaxBitrate字段");
		return FALSE;	
	}			
	MaxBitrate=strTemp.substr(VariableStart+12,VariableEnd-VariableStart-12);
	/*if( (VariableStart=strTemp.find("<Protocol>",0)) ==string::npos)			
		return FALSE;
	if ( (VariableEnd=strTemp.find("</Protocol>",VariableStart+1)) ==string::npos)		
		return FALSE;	
	Protocol=strTemp.substr(VariableStart+10,VariableEnd-VariableStart-10);*/
// 	if( (VariableStart=strTemp.find("<Multicast>",0)) ==string::npos)			
// 	{
// 		AfxMessageBox("实时流请求缺少Multicast字段");
// 		return FALSE;	
// 	}							
// 	if ( (VariableEnd=strTemp.find("</Multicast>",VariableStart+1)) ==string::npos)		
// 	{
// 		AfxMessageBox("实时流请求缺少Multicast字段");
// 		return FALSE;	
// 	}			
// 	Multicast=strTemp.substr(VariableStart+11,VariableEnd-VariableStart-11);
	/*if( (VariableStart=strTemp.find("<TransmitMode>",0)) ==string::npos)			
		return FALSE;						
	if ( (VariableEnd=strTemp.find("</TransmitMode>",VariableStart+1)) ==string::npos)		
		return FALSE;	
	TransmitMode=strTemp.substr(VariableStart+14,VariableEnd-VariableStart-14);*/
	string XmlInvite;
	XmlInvite="<?xml version=\"1.0\"?>\r\n";
	XmlInvite+="<Response>\r\n";
	XmlInvite+="<Variable>RealMedia</Variable>\r\n";
	//XmlInvite+="<Result>0</Result>\r\n";
	XmlInvite+="<Format>720";   //有的厂商不支持720，修改CIF
	//XmlInvite+=Format;
	XmlInvite+="</Format>\r\n";
	XmlInvite+="<Video>H.264";
	//XmlInvite+=Video;
	XmlInvite+="</Video>\r\n";
	XmlInvite+="<Audio>";
	XmlInvite+=Audio;
	XmlInvite+="</Audio>\r\n";
	XmlInvite+="<Bitrate>300</Bitrate>\r\n";
	//XmlInvite+="<TransmitMode>1</TransmitMode>\r\n";		
// 	XmlInvite+="<Multicast>";
// 	XmlInvite+=Multicast;
// 	XmlInvite+="</Multicast>\r\n";
	XmlInvite+="<Socket>";//192.168.1.7 UDP 2300</Socket>\r\n";
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);	
	XmlInvite+=pWnd->m_InfoClient.IP;
	XmlInvite+=" UDP 2300</Socket>\r\n";
	//XmlInvite+="<DecoderTag>manufacturer=H3C ver=V30</DecoderTag>\r\n";	
	XmlInvite+="</Response>\r\n";	
	strcpy(*strInviteXml,XmlInvite.c_str());
	return TRUE;
}

BOOL CSipMsgProcess::XmlPTZCreate(char** strPTZXml,char *srcXml)
{
	string strTemp(srcXml);		
	string UserCode;
	string PTZCommand;
	string Address;
	string Protocol;
	string::size_type VariableStart;	
	string::size_type VariableEnd;

	if( (VariableStart=strTemp.find("<Privilege>",0)) ==string::npos)			
	{
		AfxMessageBox("实时流请求缺少Privilege字段");
		return FALSE;	
	}								
	if ( (VariableEnd=strTemp.find("</Privilege>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("实时流请求缺少Privilege字段");
		return FALSE;	
	}	
	UserCode=strTemp.substr(VariableStart+11,VariableEnd-VariableStart-11);
	if( (VariableStart=strTemp.find("<Command>",0)) ==string::npos)			
	{
		AfxMessageBox("实时流请求缺少Command字段");
		return FALSE;	
	}
	if ( (VariableEnd=strTemp.find("</Command>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("实时流请求缺少Command字段");
		return FALSE;	
	}				
 	PTZCommand=strTemp.substr(VariableStart+9,VariableEnd-VariableStart-9);
// 	if( (VariableStart=strTemp.find("<Address>",0)) ==string::npos)			
// 		return FALSE;						
// 	if ( (VariableEnd=strTemp.find("</Address>",VariableStart+1)) ==string::npos)		
// 		return FALSE;	
// 	Address=strTemp.substr(VariableStart+9,VariableEnd-VariableStart-9);
	/*if( (VariableStart=strTemp.find("<Protocol>",0)) ==string::npos)			
		return FALSE;						
	if ( (VariableEnd=strTemp.find("</Protocol>",VariableStart+1)) ==string::npos)		
		return FALSE;
	Protocol=strTemp.substr(VariableStart+10,VariableEnd-VariableStart-10);*/
	string XmlPTZ;
	XmlPTZ="<?xml version=\"1.0\"?>\r\n";
	XmlPTZ+="<Response>\r\n";
	XmlPTZ+="<ControlResponse>\r\n";
	XmlPTZ+="<Variable>PTZCommand</Variable>\r\n";
	XmlPTZ+="<Result>0</Result>\r\n";
	XmlPTZ+="<Command>";
	XmlPTZ+=PTZCommand;
	XmlPTZ+="</Command>\r\n";
	XmlPTZ+="</ControlResponse>\r\n";
	XmlPTZ+="</Response>\r\n";	
	strcpy(*strPTZXml,XmlPTZ.c_str());
	return TRUE;
}

BOOL CSipMsgProcess::XmlEncoderSetCreate(char** strEncoderSetXml,char *srcXml)
{
	string strTemp(srcXml);		
	string UserCode;	
	string::size_type VariableStart;	
	string::size_type VariableEnd;
	if( (VariableStart=strTemp.find("<Privilege>",0)) ==string::npos)			
		return FALSE;						
	if ( (VariableEnd=strTemp.find("</Privilege>",VariableStart+1)) ==string::npos)		
		return FALSE;	
	UserCode=strTemp.substr(VariableStart+11,VariableEnd-VariableStart-11);	
	string XmlEncoderSet;
	XmlEncoderSet="<?xml version=\"1.0\"?>\r\n";
	XmlEncoderSet+="<Response>\r\n";
	XmlEncoderSet+="<ControlResponse>\r\n";
	XmlEncoderSet+="<Variable>EncoderSet</Variable>\r\n";
	XmlEncoderSet+="<Result>0</Result>\r\n";
	XmlEncoderSet+="<Privilege>";
	XmlEncoderSet+=UserCode;
	XmlEncoderSet+="</Privilege>\r\n";
	XmlEncoderSet+="</ControlResponse>\r\n";
	XmlEncoderSet+="</Response>\r\n";	
	strcpy(*strEncoderSetXml,XmlEncoderSet.c_str());	
	return TRUE;
}

void CSipMsgProcess::SipAlarmSubscribeNotify(char **dst,InfoServer m_InfoServer,InfoClient m_InfoClient,osip_message_t *srcmsg)
{
	char FromTag[10];
	int RandData;
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(FromTag,str);	
	char *dest=NULL;
	//远程配置信息
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//本地配置信息
	char *srcCode=(LPSTR)(LPCTSTR)m_InfoClient.UserAddress;
	char *srcUserName=(LPSTR)(LPCTSTR)m_InfoClient.UserName;
	char *srcIP=(LPSTR)(LPCTSTR)m_InfoClient.IP;
	char *srcPort=(LPSTR)(LPCTSTR)m_InfoClient.Port;
	CSipMsgProcess *SipHeader=new CSipMsgProcess;
	////////////////////////
	osip_uri_set_host(SipHeader->m_SipMsg.uriServer,dstIP);
	osip_uri_set_scheme(SipHeader->m_SipMsg.uriServer,"sip");
	osip_uri_set_username(SipHeader->m_SipMsg.uriServer,dstCode);
	osip_uri_set_port(SipHeader->m_SipMsg.uriServer,dstPort);	

	osip_uri_set_host(SipHeader->m_SipMsg.uriClient,srcIP);
	osip_uri_set_scheme(SipHeader->m_SipMsg.uriClient,"sip");
	osip_uri_set_username(SipHeader->m_SipMsg.uriClient,srcCode);
	osip_uri_set_port(SipHeader->m_SipMsg.uriClient,srcPort);

	osip_via_set_version(SipHeader->m_SipMsg.via,"2.0");
	osip_via_set_protocol(SipHeader->m_SipMsg.via,"UDP");
	osip_via_set_port(SipHeader->m_SipMsg.via,srcPort);
	//osip_via_set_branch(SipHeader->m_SipMsg.via,"z9hG4bK-94a5dd17bfa14a949e9fb8d58cbc78be");//随机数	
// 	RandData=rand();	
// 	char sdtr[10];	
// 	char branch[20];
// 	itoa(RandData,sdtr,16);
// 	strcpy(branch,"z9hG4bK--");
// 	strcat(branch,sdtr);
// 	osip_via_set_branch(SipHeader->m_SipMsg.via,branch);//随机数
	osip_via_set_host(SipHeader->m_SipMsg.via,srcIP);	
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);	
	//osip_call_id_clone(srcmsg->call_id,&SipHeader->m_SipMsg.msg->call_id);
	//osip_from_clone(srcmsg->from,&SipHeader->m_SipMsg.msg->to);	
	osip_from_set_displayname(SipHeader->m_SipMsg.from,srcUserName);
	osip_from_set_url(SipHeader->m_SipMsg.from,SipHeader->m_SipMsg.uriClient);
	if (srcmsg->to->gen_params.nb_elt==0 )
	{
		//osip_to_set_tag(SipHeader->m_SipMsg.msg->from,FromTag);
		osip_from_set_tag(SipHeader->m_SipMsg.from,pWnd->alarmTag);
	}	
	osip_to_set_displayname(SipHeader->m_SipMsg.to,dstUserName);	
	osip_to_set_url(SipHeader->m_SipMsg.to,SipHeader->m_SipMsg.uriServer);		
	//osip_from_set_displayname(SipHeader->m_SipMsg.from,srcUserName);
	//osip_from_set_tag(SipHeader->m_SipMsg.from,FromTag);//随机数
	//osip_from_set_url(SipHeader->m_SipMsg.from,SipHeader->m_SipMsg.uriClient);	

	//osip_to_set_displayname(SipHeader->m_SipMsg.to,dstUserName);	
	//osip_to_set_url(SipHeader->m_SipMsg.to,SipHeader->m_SipMsg.uriServer);

	osip_cseq_set_method(SipHeader->m_SipMsg.cseq,"NOTIFY");
	osip_cseq_set_number(SipHeader->m_SipMsg.cseq,"1");

	osip_message_set_uri(SipHeader->m_SipMsg.msg,SipHeader->m_SipMsg.uriServer);
	osip_message_set_method(SipHeader->m_SipMsg.msg,"NOTIFY");

	osip_contact_set_url(SipHeader->m_SipMsg.contact,SipHeader->m_SipMsg.uriClient);
	osip_contact_set_displayname(SipHeader->m_SipMsg.contact,srcUserName);
	osip_message_set_max_forwards(SipHeader->m_SipMsg.msg,"70");

	osip_uri_param_t *h;
	osip_uri_param_init(&h);
	osip_from_get_tag(srcmsg->from,&h);
	char Tag[50];
	strcpy(Tag,h->gvalue);	
	osip_to_set_tag(SipHeader->m_SipMsg.to,Tag);

	osip_to_to_str(SipHeader->m_SipMsg.to,&dest);
	osip_message_set_to(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);	
	//there call id is alarm subscribe call id
	if ( strcmp(srcmsg->call_id->host,"")==0 )
	{	
		osip_call_id_set_number(SipHeader->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(SipHeader->m_SipMsg.callid,&dest);
		osip_message_set_call_id(SipHeader->m_SipMsg.msg,dest);
		osip_free(dest);
	}
	else
		osip_call_id_clone(srcmsg->call_id,&SipHeader->m_SipMsg.msg->call_id);
	//osip_message_set_call_id(SipHeader->m_SipMsg.msg,pWnd->AlarmCallID);

	osip_from_to_str(SipHeader->m_SipMsg.from,&dest);
	osip_message_set_from(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_contact_to_str(SipHeader->m_SipMsg.contact,&dest);
	osip_message_set_contact(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_cseq_to_str(SipHeader->m_SipMsg.cseq,&dest);
	osip_message_set_cseq(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_via_to_str(SipHeader->m_SipMsg.via,&dest);
	osip_message_set_via(SipHeader->m_SipMsg.msg,dest);
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
	CString st0;
	if (1==i)
	{

		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(SipHeader->m_SipMsg.msg,dest);
		st0=dest;
		st0="Via: "+st0+"\r\n";		
	}
	else
	{
		st0="";
	}
	osip_free(dest);

	size_t length;	
	osip_message_to_str(SipHeader->m_SipMsg.msg,&dest,&length);	

	string st="Subscription-State: active;expires=90;retry-after=0\r\n";
	st+="Event:presence\r\n";
	string strtemp=dest;
	int index=strtemp.find("Content-Length");
	strtemp.insert(index,st);

	strcpy(*dst,strtemp.c_str());
	//strcpy(*dst,dest);
	osip_free(dest);
	osip_uri_param_free(h);
}

BOOL CSipMsgProcess::XmlAlarmCreate(char** strAlarmXml,char *srcXml)
{
	string strTemp(srcXml);	
	string::size_type VariableStart;	
	string::size_type VariableEnd;	
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	if( (VariableStart=strTemp.find("<Variable>",0)) ==string::npos)			
	{
		AfxMessageBox("报警，缺Variable字段");
		return FALSE;
	}					
	if ( (VariableEnd=strTemp.find("</Variable>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("报警，缺Variable字段");
		return FALSE;
	}	
	
	if( (VariableStart=strTemp.find("<Privilege>",0)) ==string::npos)			
	{
		AfxMessageBox("报警，缺Privilege字段");
		return FALSE;
	}							
	if ( (VariableEnd=strTemp.find("</Privilege>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("报警，缺Privilege字段");
		return FALSE;
	}	
	pWnd->m_InfoAlarm.UserCode=strTemp.substr(VariableStart+11,VariableEnd-VariableStart-11);
	
// 	if( (VariableStart=strTemp.find("<Level>",0)) ==string::npos)			
// 		return FALSE;						
// 	if ( (VariableEnd=strTemp.find("</Level>",VariableStart+1)) ==string::npos)		
// 		return FALSE;
// 	pWnd->m_InfoAlarm.Level=strTemp.substr(VariableStart+7,VariableEnd-VariableStart-7);
	
	if( (VariableStart=strTemp.find("<AlarmType>",0)) ==string::npos)			
	{
		AfxMessageBox("报警，缺AlarmType字段");
		return FALSE;
	}						
	if ( (VariableEnd=strTemp.find("</AlarmType>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("报警，缺AlarmType字段");
		return FALSE;
	}
	pWnd->m_InfoAlarm.AlarmType=strTemp.substr(VariableStart+11,VariableEnd-VariableStart-11);
	
	if( (VariableStart=strTemp.find("<Address>",0)) ==string::npos)			
	{
		AfxMessageBox("报警，缺Address字段");
		return FALSE;
	}					
	if ( (VariableEnd=strTemp.find("</Address>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("报警，缺Address字段");
		return FALSE;
	}
	pWnd->m_InfoAlarm.Address=strTemp.substr(VariableStart+9,VariableEnd-VariableStart-9);
	
// 	if( (VariableStart=strTemp.find("<AcceptIp>",0)) ==string::npos)			
// 		return FALSE;						
// 	if ( (VariableEnd=strTemp.find("</AcceptIp>",VariableStart+1)) ==string::npos)		
// 		return FALSE;
// 	pWnd->m_InfoAlarm.AcceptIP=strTemp.substr(VariableStart+10,VariableEnd-VariableStart-10);
// 	
// 	if( (VariableStart=strTemp.find("<AcceptPort>",0)) ==string::npos)			
// 		return FALSE;						
// 	if ( (VariableEnd=strTemp.find("</AcceptPort>",VariableStart+1)) ==string::npos)		
// 		return FALSE;
// 	pWnd->m_InfoAlarm.AcceptPort=strTemp.substr(VariableStart+12,VariableEnd-VariableStart-12);
	
	string XmlAlarmSet;
	XmlAlarmSet="<?xml version=\"1.0\"?>\r\n";
	XmlAlarmSet+="<Response>\r\n";
	XmlAlarmSet+="<Variable>AlarmSubscribe</Variable>\r\n";	
	XmlAlarmSet+="<Result>0</Result>\r\n";	
	XmlAlarmSet+="</Response>\r\n";
	strcpy(*strAlarmXml,XmlAlarmSet.c_str());	
	return TRUE;
}

void CSipMsgProcess::SipXmlMsg(char **dst,InfoServer m_InfoServer,InfoClient m_InfoClient,char *Xml)
{
	char FromTag[10];
	char CallID[10];
	//远程配置信息
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//本地配置信息
	char *srcCode=(LPSTR)(LPCTSTR)m_InfoClient.UserAddress;
	char *srcUserName=(LPSTR)(LPCTSTR)m_InfoClient.UserName;
	char *srcIP=(LPSTR)(LPCTSTR)m_InfoClient.IP;
	char *srcPort=(LPSTR)(LPCTSTR)m_InfoClient.Port;

	int RandData;
	srand((unsigned int)time(0));
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(FromTag,str);
	RandData=rand();
	itoa(RandData,str,10);
	strcpy(CallID,str);

	char *dest;
	CSipMsgProcess *SipHeader=new CSipMsgProcess;
	////////////////////////
	osip_uri_set_host(SipHeader->m_SipMsg.uriServer,dstIP);
	osip_uri_set_scheme(SipHeader->m_SipMsg.uriServer,"sip");
	osip_uri_set_username(SipHeader->m_SipMsg.uriServer,dstCode);
	osip_uri_set_port(SipHeader->m_SipMsg.uriServer,dstPort);	

	osip_uri_set_host(SipHeader->m_SipMsg.uriClient,srcIP);
	osip_uri_set_scheme(SipHeader->m_SipMsg.uriClient,"sip");
	osip_uri_set_username(SipHeader->m_SipMsg.uriClient,srcCode);
	osip_uri_set_port(SipHeader->m_SipMsg.uriClient,srcPort);

	osip_via_set_version(SipHeader->m_SipMsg.via,"2.0");
	osip_via_set_protocol(SipHeader->m_SipMsg.via,"UDP");
	osip_via_set_port(SipHeader->m_SipMsg.via,srcPort);
	//osip_via_set_branch(via,"123456789");//随机数
// 	RandData=rand();	
// 	char sdtr[10];	
// 	char branch[20];
// 	itoa(RandData,sdtr,16);
// 	strcpy(branch,"z9hG4bK--");
// 	strcat(branch,sdtr);
// 	osip_via_set_branch(SipHeader->m_SipMsg.via,branch);//随机数
	//osip_via_set_branch(SipHeader->m_SipMsg.via,"z9hG4bK--22bd9222");//随机数
	osip_via_set_host(SipHeader->m_SipMsg.via,srcIP);

	osip_call_id_set_host(SipHeader->m_SipMsg.callid,srcIP);
	osip_call_id_set_number(SipHeader->m_SipMsg.callid,CallID);//随机数

	//osip_from_set_displayname(SipHeader->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipHeader->m_SipMsg.from,FromTag);//随机数
	osip_from_set_url(SipHeader->m_SipMsg.from,SipHeader->m_SipMsg.uriClient);
	//保留本注册的消息的CallID信息		
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	memset(pWnd->TimeSetID.Host,0,HOSTSIZE);
	memset(pWnd->TimeSetID.Num,0,NUMSIZE);
	memset(pWnd->TimeSetID.Tag,0,NUMSIZE);
	strcpy(pWnd->TimeSetID.Host,srcIP);
	strcpy(pWnd->TimeSetID.Num,CallID);
	strcpy(pWnd->TimeSetID.Tag,FromTag);
	//osip_to_set_displayname(SipHeader->m_SipMsg.to,dstUserName);	
	osip_to_set_url(SipHeader->m_SipMsg.to,SipHeader->m_SipMsg.uriServer);

	osip_cseq_set_method(SipHeader->m_SipMsg.cseq,"DO");
	osip_cseq_set_number(SipHeader->m_SipMsg.cseq,"1");

	osip_message_set_uri(SipHeader->m_SipMsg.msg,SipHeader->m_SipMsg.uriServer);
	osip_message_set_method(SipHeader->m_SipMsg.msg,"DO");

	osip_contact_set_url(SipHeader->m_SipMsg.contact,SipHeader->m_SipMsg.uriClient);
	osip_contact_set_displayname(SipHeader->m_SipMsg.contact,srcUserName);
	osip_message_set_max_forwards(SipHeader->m_SipMsg.msg,"70");

	osip_to_to_str(SipHeader->m_SipMsg.to,&dest);
	osip_message_set_to(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_call_id_to_str(SipHeader->m_SipMsg.callid,&dest);
	osip_message_set_call_id(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_from_to_str(SipHeader->m_SipMsg.from,&dest);
	osip_message_set_from(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_contact_to_str(SipHeader->m_SipMsg.contact,&dest);
	osip_message_set_contact(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_cseq_to_str(SipHeader->m_SipMsg.cseq,&dest);
	osip_message_set_cseq(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_via_to_str(SipHeader->m_SipMsg.via,&dest);
	osip_message_set_via(SipHeader->m_SipMsg.msg,dest);
// 	CSipMsgProcess *Sip200=new CSipMsgProcess;
// 	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
// 	CString st0;
// 	if (1==i)
// 	{
// 
// 		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
// 		osip_message_set_via(SipHeader->m_SipMsg.msg,dest);
// 		st0=dest;
// 		st0="Via: "+st0+"\r\n";		
// 	}
// 	else
// 	{
// 		st0="";
// 	}
	osip_free(dest);	
	osip_message_set_content_type(SipHeader->m_SipMsg.msg,"Application/DDCP");
	osip_message_set_body(SipHeader->m_SipMsg.msg,Xml,strlen(Xml));
	size_t length;	
	osip_message_to_str(SipHeader->m_SipMsg.msg,&dest,&length);	
	strcpy(*dst,dest);
	osip_free(dest);

}

void CSipMsgProcess::SipAlarmNotifyXmlMsg(char **dst,InfoServer m_InfoServer,InfoClient m_InfoClient,char *Xml)
{
	char FromTag[10];	
	//远程配置信息
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//本地配置信息
	char *srcCode=(LPSTR)(LPCTSTR)m_InfoClient.UserAddress;
	char *srcUserName=(LPSTR)(LPCTSTR)m_InfoClient.UserName;
	char *srcIP=(LPSTR)(LPCTSTR)m_InfoClient.IP;
	char *srcPort=(LPSTR)(LPCTSTR)m_InfoClient.Port;

	int RandData;	
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(FromTag,str);
	RandData=rand();
	char *dest;
	CSipMsgProcess *SipHeader=new CSipMsgProcess;
	////////////////////////
	osip_uri_set_host(SipHeader->m_SipMsg.uriServer,dstIP);
	osip_uri_set_scheme(SipHeader->m_SipMsg.uriServer,"sip");
	osip_uri_set_username(SipHeader->m_SipMsg.uriServer,dstCode);
	osip_uri_set_port(SipHeader->m_SipMsg.uriServer,dstPort);	

	osip_uri_set_host(SipHeader->m_SipMsg.uriClient,srcIP);
	osip_uri_set_scheme(SipHeader->m_SipMsg.uriClient,"sip");
	osip_uri_set_username(SipHeader->m_SipMsg.uriClient,srcCode);
	osip_uri_set_port(SipHeader->m_SipMsg.uriClient,srcPort);

	osip_via_set_version(SipHeader->m_SipMsg.via,"2.0");
	osip_via_set_protocol(SipHeader->m_SipMsg.via,"UDP");
	osip_via_set_port(SipHeader->m_SipMsg.via,srcPort);
	//osip_via_set_branch(via,"123456789");//随机数
	//osip_via_set_branch(SipHeader->m_SipMsg.via,"z9hG4bK--22cd7222");//随机数
// 	RandData=rand();	
// 	char sdtr[8];	
// 	char branch[20];
// 	itoa(RandData,sdtr,16);	
// 	strcpy(branch,"z9hG4bK-");
// 	strcat(branch,sdtr);
// 	osip_via_set_branch(SipHeader->m_SipMsg.via,branch);//随机数
	osip_via_set_host(SipHeader->m_SipMsg.via,srcIP);
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	//osip_from_set_displayname(SipHeader->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipHeader->m_SipMsg.from,FromTag);//随机数
	osip_from_set_url(SipHeader->m_SipMsg.from,SipHeader->m_SipMsg.uriClient);	

	//osip_to_set_displayname(SipHeader->m_SipMsg.to,dstUserName);
	osip_to_set_url(SipHeader->m_SipMsg.to,SipHeader->m_SipMsg.uriServer);

	osip_cseq_set_method(SipHeader->m_SipMsg.cseq,"NOTIFY");
	osip_cseq_set_number(SipHeader->m_SipMsg.cseq,"2");

	osip_message_set_uri(SipHeader->m_SipMsg.msg,SipHeader->m_SipMsg.uriServer);
	osip_message_set_method(SipHeader->m_SipMsg.msg,"NOTIFY");

	osip_contact_set_url(SipHeader->m_SipMsg.contact,SipHeader->m_SipMsg.uriClient);
	osip_contact_set_displayname(SipHeader->m_SipMsg.contact,srcUserName);
	osip_message_set_max_forwards(SipHeader->m_SipMsg.msg,"70");

	osip_to_to_str(SipHeader->m_SipMsg.to,&dest);
	osip_message_set_to(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);
	// there call id is alarm subscribe call id	
	osip_message_set_call_id(SipHeader->m_SipMsg.msg,pWnd->AlarmCallID);	

	osip_from_to_str(SipHeader->m_SipMsg.from,&dest);
	osip_message_set_from(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_contact_to_str(SipHeader->m_SipMsg.contact,&dest);
	osip_message_set_contact(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_cseq_to_str(SipHeader->m_SipMsg.cseq,&dest);
	osip_message_set_cseq(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_via_to_str(SipHeader->m_SipMsg.via,&dest);
	osip_message_set_via(SipHeader->m_SipMsg.msg,dest);
	//CSipMsgProcess *Sip200=new CSipMsgProcess;
// 	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
// 	CString st0;
// 	if (1==i)
// 	{
// 
// 		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
// 		osip_message_set_via(SipHeader->m_SipMsg.msg,dest);
// 		st0=dest;
// 		st0="Via: "+st0+"\r\n";		
// 	}
// 	else
// 	{
// 		st0="";
// 	}
	osip_free(dest);	
	osip_message_set_content_type(SipHeader->m_SipMsg.msg,"Application/DDCP");
	osip_message_set_body(SipHeader->m_SipMsg.msg,Xml,strlen(Xml));
	size_t length;	
	osip_message_to_str(SipHeader->m_SipMsg.msg,&dest,&length);	

	string st="Subscription-State: active;expires=90;retry-after=0\r\n";
	st+="Event:presence\r\n";
	string strtemp=dest;
	int index=strtemp.find("Content-Type");
	strtemp.insert(index,st);

	strcpy(*dst,strtemp.c_str());

	//strcpy(*dst,dest);
	osip_free(dest);
}

void CSipMsgProcess::SipNotifyXmlMsg(char **dst,InfoServer m_InfoServer,InfoClient m_InfoClient,char *Xml)
{
	char FromTag[10];	
	//远程配置信息
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//本地配置信息
	char *srcCode=(LPSTR)(LPCTSTR)m_InfoClient.UserAddress;
	char *srcUserName=(LPSTR)(LPCTSTR)m_InfoClient.UserName;
	char *srcIP=(LPSTR)(LPCTSTR)m_InfoClient.IP;
	char *srcPort=(LPSTR)(LPCTSTR)m_InfoClient.Port;

	int RandData;	
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(FromTag,str);
	RandData=rand();
	char *dest;
	CSipMsgProcess *SipHeader=new CSipMsgProcess;
	////////////////////////
	osip_uri_set_host(SipHeader->m_SipMsg.uriServer,dstIP);
	osip_uri_set_scheme(SipHeader->m_SipMsg.uriServer,"sip");
	osip_uri_set_username(SipHeader->m_SipMsg.uriServer,dstCode);
	osip_uri_set_port(SipHeader->m_SipMsg.uriServer,dstPort);	

	osip_uri_set_host(SipHeader->m_SipMsg.uriClient,srcIP);
	osip_uri_set_scheme(SipHeader->m_SipMsg.uriClient,"sip");
	osip_uri_set_username(SipHeader->m_SipMsg.uriClient,srcCode);
	osip_uri_set_port(SipHeader->m_SipMsg.uriClient,srcPort);

	osip_via_set_version(SipHeader->m_SipMsg.via,"2.0");
	osip_via_set_protocol(SipHeader->m_SipMsg.via,"UDP");
	osip_via_set_port(SipHeader->m_SipMsg.via,srcPort);
	//osip_via_set_branch(via,"123456789");//随机数
	//osip_via_set_branch(SipHeader->m_SipMsg.via,"z9hG4bK--22cd7222");//随机数
	// 	RandData=rand();	
	// 	char sdtr[8];	
	// 	char branch[20];
	// 	itoa(RandData,sdtr,16);	
	// 	strcpy(branch,"z9hG4bK-");
	// 	strcat(branch,sdtr);
	// 	osip_via_set_branch(SipHeader->m_SipMsg.via,branch);//随机数
	osip_via_set_host(SipHeader->m_SipMsg.via,srcIP);
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	//osip_from_set_displayname(SipHeader->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipHeader->m_SipMsg.from,FromTag);//随机数
	osip_from_set_url(SipHeader->m_SipMsg.from,SipHeader->m_SipMsg.uriClient);	

	//osip_to_set_displayname(SipHeader->m_SipMsg.to,dstUserName);
	osip_to_set_url(SipHeader->m_SipMsg.to,SipHeader->m_SipMsg.uriServer);

	osip_cseq_set_method(SipHeader->m_SipMsg.cseq,"NOTIFY");
	osip_cseq_set_number(SipHeader->m_SipMsg.cseq,"1");

	osip_message_set_uri(SipHeader->m_SipMsg.msg,SipHeader->m_SipMsg.uriServer);
	osip_message_set_method(SipHeader->m_SipMsg.msg,"NOTIFY");

	osip_contact_set_url(SipHeader->m_SipMsg.contact,SipHeader->m_SipMsg.uriClient);
	osip_contact_set_displayname(SipHeader->m_SipMsg.contact,srcUserName);
	osip_message_set_max_forwards(SipHeader->m_SipMsg.msg,"70");

	osip_to_to_str(SipHeader->m_SipMsg.to,&dest);
	osip_message_set_to(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);
	// there call id is alarm subscribe call id	
	osip_message_set_call_id(SipHeader->m_SipMsg.msg,FromTag);	

	osip_from_to_str(SipHeader->m_SipMsg.from,&dest);
	osip_message_set_from(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_contact_to_str(SipHeader->m_SipMsg.contact,&dest);
	osip_message_set_contact(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_cseq_to_str(SipHeader->m_SipMsg.cseq,&dest);
	osip_message_set_cseq(SipHeader->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_via_to_str(SipHeader->m_SipMsg.via,&dest);
	osip_message_set_via(SipHeader->m_SipMsg.msg,dest);
// 	CSipMsgProcess *Sip200=new CSipMsgProcess;
// 	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
// 	CString st0;
// 	if (1==i)
// 	{
// 
// 		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
// 		osip_message_set_via(SipHeader->m_SipMsg.msg,dest);
// 		st0=dest;
// 		st0="Via: "+st0+"\r\n";		
// 	}
// 	else
// 	{
// 		st0="";
// 	}
	osip_free(dest);	
	osip_message_set_content_type(SipHeader->m_SipMsg.msg,"Application/DDCP");
	osip_message_set_body(SipHeader->m_SipMsg.msg,Xml,strlen(Xml));
	size_t length;	
	osip_message_to_str(SipHeader->m_SipMsg.msg,&dest,&length);	

	string st="Subscription-State: active;expires=90;retry-after=0\r\n";
	st+="Event:presence\r\n";
	string strtemp=dest;
	int index=strtemp.find("Content-Type");
	strtemp.insert(index,st);

	strcpy(*dst,strtemp.c_str());

	//strcpy(*dst,dest);
	osip_free(dest);
}

BOOL CSipMsgProcess::SipVerify(InfoServer m_InfoServer,InfoClient m_InfoClient,osip_message_t *srcMsg,int nto)
{
	//远程配置信息
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//本地配置信息
	char *srcCode=(LPSTR)(LPCTSTR)m_InfoClient.UserAddress;
	char *srcUserName=(LPSTR)(LPCTSTR)m_InfoClient.UserName;
	char *srcIP=(LPSTR)(LPCTSTR)m_InfoClient.IP;
	char *srcPort=(LPSTR)(LPCTSTR)m_InfoClient.Port;
	if (srcMsg->from->url->username==NULL)
	{
		srcMsg->from->url->username="";		
	}
	if (srcMsg->from->displayname==NULL )
	{
		srcMsg->from->displayname="";
	}
	if (srcMsg->from->url->host==NULL)
	{
		srcMsg->from->url->host="";
	}
	if (srcMsg->from->url->port==NULL)
	{
		srcMsg->from->url->port="";
	}
	if (srcMsg->to->url->username==NULL)
	{
		srcMsg->to->url->username="";
	}
	if (srcMsg->to->displayname==NULL)
	{
		srcMsg->to->displayname="";
	}
	if (srcMsg->to->url->host==NULL)
	{
		srcMsg->to->url->host="";
	}
	if (srcMsg->to->url->port==NULL)
	{
		srcMsg->to->url->port="";
	}
	if ( nto==1 )
	{
		//strcmp(srcUserName,srcMsg->from->displayname)==0 &&
		//strcmp(dstUserName,srcMsg->to->displayname)==0 &&
		if ( strcmp(srcCode,srcMsg->from->url->username)==0 &&			
			strcmp(srcIP,srcMsg->from->url->host)==0 &&
			strcmp(srcPort,srcMsg->from->url->port)==0 &&
			strcmp(dstCode,srcMsg->to->url->username)==0 &&			
			strcmp(dstIP,srcMsg->to->url->host)==0 &&
			strcmp(dstPort,srcMsg->to->url->port)==0 )
		{
			return TRUE;
		}
	}
	else if ( nto==0 )
	{
		//strcmp(dstUserName,srcMsg->from->displayname)==0 &&
			//strcmp(srcUserName,srcMsg->to->displayname)==0 &&
		if ( strcmp(dstCode,srcMsg->from->url->username)==0 && 			
			strcmp(dstIP,srcMsg->from->url->host)==0 &&
			strcmp(dstPort,srcMsg->from->url->port)==0 &&
			strcmp(srcCode,srcMsg->to->url->username)==0 && 			
			strcmp(srcIP,srcMsg->to->url->host)==0 &&
			strcmp(srcPort,srcMsg->to->url->port)==0 )
		{
			return TRUE;
		}
	}
	else
	{
		return TRUE;
	}
	return FALSE;	
}

BOOL CSipMsgProcess::RegisterSipVerify(InfoServer m_InfoServer,InfoClient m_InfoClient,osip_message_t *srcMsg,int nto)
{
	//远程配置信息
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//本地配置信息
	char *srcCode=(LPSTR)(LPCTSTR)m_InfoClient.UserAddress;
	char *srcUserName=(LPSTR)(LPCTSTR)m_InfoClient.UserName;
	char *srcIP=(LPSTR)(LPCTSTR)m_InfoClient.IP;
	char *srcPort=(LPSTR)(LPCTSTR)m_InfoClient.Port;
	if (srcMsg->from->url->username==NULL)
	{
		srcMsg->from->url->username="";		
	}
	if (srcMsg->from->displayname==NULL )
	{
		srcMsg->from->displayname="";
	}
	if (srcMsg->from->url->host==NULL)
	{
		srcMsg->from->url->host="";
	}
	if (srcMsg->from->url->port==NULL)
	{
		srcMsg->from->url->port="";
	}
	if (srcMsg->to->url->username==NULL)
	{
		srcMsg->to->url->username="";
	}
	if (srcMsg->to->displayname==NULL)
	{
		srcMsg->to->displayname="";
	}
	if (srcMsg->to->url->host==NULL)
	{
		srcMsg->to->url->host="";
	}
	if (srcMsg->to->url->port==NULL)
	{
		srcMsg->to->url->port="";
	}
	if ( nto==1 )
	{
		//strcmp(srcUserName,srcMsg->from->displayname)==0 &&
		//strcmp(dstUserName,srcMsg->to->displayname)==0 &&
		if ( strcmp(srcCode,srcMsg->from->url->username)==0 &&			
			strcmp(srcIP,srcMsg->from->url->host)==0 &&
			strcmp(srcPort,srcMsg->from->url->port)==0 &&
			strcmp(srcCode,srcMsg->to->url->username)==0 &&			
			strcmp(srcIP,srcMsg->to->url->host)==0 &&
			strcmp(srcPort,srcMsg->to->url->port)==0 )
		{
			return TRUE;
		}
	}
	else if ( nto==0 )
	{
		//strcmp(dstUserName,srcMsg->from->displayname)==0 &&
		//strcmp(srcUserName,srcMsg->to->displayname)==0 &&
		if ( strcmp(dstCode,srcMsg->from->url->username)==0 && 			
			strcmp(dstIP,srcMsg->from->url->host)==0 &&
			strcmp(dstPort,srcMsg->from->url->port)==0 &&
			strcmp(srcCode,srcMsg->to->url->username)==0 && 			
			strcmp(srcIP,srcMsg->to->url->host)==0 &&
			strcmp(srcPort,srcMsg->to->url->port)==0 )
		{
			return TRUE;
		}
	}
	else
	{
		return TRUE;
	}
	return FALSE;	
}

int CSipMsgProcess::CreateXMLptzPreBitQuery_c(char **dstXML,int begin,int end)
{
	CString strTemp;
	strTemp="<?xml version=\"1.0\"?>\r\n";
	strTemp+="<Response>\r\n";
	strTemp+="<QueryResponse>\r\n";
	strTemp+="<Variable>PresetList</Variable>\r\n";
	strTemp+="<Result>0</Result>\r\n";
	strTemp+="<RealNum>49</RealNum>\r\n";
	CString cst;
	cst.Format("%d",begin);
	strTemp+="<FromIndex>"+cst+"</FromIndex>\r\n";
	cst.Format("%d",end);
	strTemp+="<ToIndex>"+cst+"</ToIndex>\r\n";
// 	strTemp+="<FromIndex>1</FromIndex>\r\n";	
// 	strTemp+="<ToIndex>2</ToIndex>\r\n";
	//strTemp+="<RemainPresetNum>0</RemainPresetNum>\r\n";
	strTemp+="<PresetInfoList>\r\n";

	for (int i=(begin-1)*4;i<end*4;i++)
	{
		strTemp+=PresetInfoList[i]+"\r\n";
	}
	strTemp+="</PresetInfoList>\r\n";			
	strTemp+="</QueryResponse>\r\n";
	strTemp+="</Response>\r\n";
	char *dst=(LPSTR)(LPCTSTR)strTemp;	
	strcpy(*dstXML,dst);
	return 0;
}

int CSipMsgProcess::CreateXMLVideoQuery(char **dstXML)
{
	CString strTemp;
	strTemp="<?xml version=\"1.0\"?>\r\n";
	strTemp+="<Response>\r\n";
	strTemp+="<QueryResponse>\r\n";
	strTemp+="<Variable>FileList</Variable>\r\n";
	strTemp+="<Result>0</Result>\r\n";	
	strTemp+="<RealFileNum>49</RealFileNum>\r\n";
	strTemp+="<FromIndex>1</FromIndex>\r\n";
	strTemp+="<ToIndex>5</ToIndex>\r\n";
	//strTemp+="<DecoderTag>Manufacturer=H3C ver=V30</DecoderTag>\r\n";
	strTemp+="<FileInfoList>\r\n";

	strTemp+="<Item>\r\n";
	strTemp+="<Name>xiaoshan_20051101001.mp4</Name>\r\n";
	strTemp+="<BeginTime>20051110T132050Z</BeginTime>\r\n";
	strTemp+="<EndTime>20051110T133050Z</EndTime>\r\n";
	strTemp+="<FileSize>500000</FileSize>\r\n";	
	strTemp+="</Item>\r\n";

	strTemp+="<Item>\r\n";
	strTemp+="<Name>xiaoshan_20051101002.mp4</Name>\r\n";
	strTemp+="<BeginTime>20051110T133050Z</BeginTime>\r\n";
	strTemp+="<EndTime>20051110T134050Z</EndTime>\r\n";
	strTemp+="<FileSize>500000</FileSize>\r\n";	
	strTemp+="</Item>\r\n";

	strTemp+="<Item>\r\n";
	strTemp+="<Name>0603_000328_091112_122000.ts</Name>\r\n";
	strTemp+="<CreationTime>2009-11-12T12:20:00Z</CreationTime>\r\n";
	strTemp+="<LastWriteTime>2009-11-12T12:30:00Z</LastWriteTime>\r\n";
	strTemp+="<FileSize>500000</FileSize>\r\n";	
	strTemp+="</Item>\r\n";

	strTemp+="<Item>\r\n";
	strTemp+="<Name>0603_000328_091112_123000.ts</Name>\r\n";
	strTemp+="<CreationTime>2009-11-12T12:30:00Z</CreationTime>\r\n";
	strTemp+="<LastWriteTime>2009-11-12T12:40:00Z</LastWriteTime>\r\n";
	strTemp+="<FileSize>500000</FileSize>\r\n";	
	strTemp+="</Item>\r\n";

	strTemp+="<Item>\r\n";
	strTemp+="<Name>0603_000328_091112_124000.ts</Name>\r\n";
	strTemp+="<CreationTime>2009-11-12T12:40:00Z</CreationTime>\r\n";
	strTemp+="<LastWriteTime>2009-11-12T12:50:00Z</LastWriteTime>\r\n";
	strTemp+="<FileSize>500000</FileSize>\r\n";	
	strTemp+="</Item>\r\n";

	strTemp+="</FileInfoList>\r\n";
	strTemp+="</QueryResponse>\r\n";
	strTemp+="</Response>\r\n";
	char *dst=(LPSTR)(LPCTSTR)strTemp;	
	strcpy(*dstXML,dst);
	return 0;
}

int CSipMsgProcess::CreateXMLVideoQuery_c(char **dstXML,int begin,int end)
{
	CString strTemp;
	strTemp="<?xml version=\"1.0\"?>\r\n";
	strTemp+="<Response>\r\n";
	strTemp+="<QueryResponse>\r\n";
	strTemp+="<Variable>FileList</Variable>\r\n";
	strTemp+="<Result>0</Result>\r\n";	
	strTemp+="<RealFileNum>49</RealFileNum>\r\n";
	CString cst;
	cst.Format("%d",begin);
	strTemp+="<FromIndex>"+cst+"</FromIndex>\r\n";
	cst.Format("%d",end);
	strTemp+="<ToIndex>"+cst+"</ToIndex>\r\n";
	//strTemp+="<DecoderTag>Manufacturer=H3C ver=V30</DecoderTag>\r\n";
	strTemp+="<FileInfoList>\r\n";

	for (int i=(begin-1)*6;i<end*6;i++)
	{
		strTemp+=HistoryVideoList[i]+"\r\n";
	}
// 	strTemp+="<Item>\r\n";
// 	strTemp+="<Name>xiaoshan_20051101001.mp4</Name>\r\n";
// 	strTemp+="<BeginTime>20051110T132050Z</BeginTime>\r\n";
// 	strTemp+="<EndTime>20051110T133050Z</EndTime>\r\n";
// 	strTemp+="<FileSize>500000</FileSize>\r\n";	
// 	strTemp+="</Item>\r\n";
// 
// 	strTemp+="<Item>\r\n";
// 	strTemp+="<Name>xiaoshan_20051101002.mp4</Name>\r\n";
// 	strTemp+="<BeginTime>20051110T133050Z</BeginTime>\r\n";
// 	strTemp+="<EndTime>20051110T134050Z</EndTime>\r\n";
// 	strTemp+="<FileSize>500000</FileSize>\r\n";	
// 	strTemp+="</Item>\r\n";
// 
// 	strTemp+="<Item>\r\n";
// 	strTemp+="<Name>0603_000328_091112_122000.ts</Name>\r\n";
// 	strTemp+="<CreationTime>2009-11-12T12:20:00Z</CreationTime>\r\n";
// 	strTemp+="<LastWriteTime>2009-11-12T12:30:00Z</LastWriteTime>\r\n";
// 	strTemp+="<FileSize>500000</FileSize>\r\n";	
// 	strTemp+="</Item>\r\n";
// 
// 	strTemp+="<Item>\r\n";
// 	strTemp+="<Name>0603_000328_091112_123000.ts</Name>\r\n";
// 	strTemp+="<CreationTime>2009-11-12T12:30:00Z</CreationTime>\r\n";
// 	strTemp+="<LastWriteTime>2009-11-12T12:40:00Z</LastWriteTime>\r\n";
// 	strTemp+="<FileSize>500000</FileSize>\r\n";	
// 	strTemp+="</Item>\r\n";
// 
// 	strTemp+="<Item>\r\n";
// 	strTemp+="<Name>0603_000328_091112_124000.ts</Name>\r\n";
// 	strTemp+="<CreationTime>2009-11-12T12:40:00Z</CreationTime>\r\n";
// 	strTemp+="<LastWriteTime>2009-11-12T12:50:00Z</LastWriteTime>\r\n";
// 	strTemp+="<FileSize>500000</FileSize>\r\n";	
// 	strTemp+="</Item>\r\n";

	strTemp+="</FileInfoList>\r\n";
	strTemp+="</QueryResponse>\r\n";
	strTemp+="</Response>\r\n";
	char *dst=(LPSTR)(LPCTSTR)strTemp;	
	strcpy(*dstXML,dst);
	return 0;
}

int CSipMsgProcess::CreateXMLCatalogQuery(char **dstXML)
{
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	CString strTemp;
	strTemp="<?xml version=\"1.0\"?>\r\n";
	strTemp+="<Response>\r\n";
	strTemp+="<QueryResponse>\r\n";
	strTemp+="<Variable>ItemList</Variable>\r\n";
	strTemp+="<Parent>"+pWnd->m_InfoClient.UserAddress+"</Parent>\r\n";	
	strTemp+="<TotalSubNum>30</TotalSubNum>\r\n";
	strTemp+="<TotalOnlineSubNum>2</TotalOnlineSubNum>\r\n";
	strTemp+="<FromIndex>1</FromIndex>\r\n";
	strTemp+="<ToIndex>2</ToIndex>\r\n";
	strTemp+="<SubNum>2</SubNum>\r\n";
	strTemp+="<SubList>\r\n";

	strTemp+="<Item>\r\n";
	strTemp+="<Name>IPC</Name>\r\n";
	strTemp+="<Address>252000001103002001</Address>\r\n";
	strTemp+="<ResType>1</ResType>\r\n";
	strTemp+="<ResSubType>1</ResSubType>\r\n";
	strTemp+="<Privilege>%02</Privilege>\r\n";
	strTemp+="<Status>0</Status>\r\n";
	strTemp+="<Longitude>23</Longitude>\r\n";
	strTemp+="<Latitude>78</Latitude>\r\n";
	strTemp+="<Elevation>532</Elevation>\r\n";
	 strTemp+="<Roadway>523</Roadway>\r\n";
	 strTemp+="<PileNo>245</PileNo>\r\n";
	 strTemp+="<AreaNo>1</AreaNo>\r\n";
	 strTemp+="<UpdateTime>20130418T120000Z</UpdateTime>\r\n";
	 strTemp+="</Item>\r\n";

	 strTemp+="<Item>\r\n";
	 strTemp+="<Name>CATLOG</Name>\r\n";
	 strTemp+="<Address>252000001199002001</Address>\r\n";
	 strTemp+="<ResType>0</ResType>\r\n";
	 strTemp+="<ResSubType>0</ResSubType>\r\n";
	 strTemp+="<Privilege>%00%01</Privilege>\r\n";
	 strTemp+="<Status>0</Status>\r\n";
	 strTemp+="<Longitude>54</Longitude>\r\n";
	 strTemp+="<Latitude>453</Latitude>\r\n";
	 strTemp+="<Elevation>35</Elevation>\r\n";
	 strTemp+="<Roadway>42</Roadway>\r\n";
	 strTemp+="<PileNo>52</PileNo>\r\n";
	 strTemp+="<AreaNo>1</AreaNo>\r\n";
	 strTemp+="<UpdateTime>20130422T130000Z</UpdateTime>\r\n";
	 strTemp+="</Item>\r\n";
	 strTemp+="</SubList>\r\n";
	 strTemp+="</QueryResponse>\r\n";
	 strTemp+="</Response>\r\n";

	char *dst=(LPSTR)(LPCTSTR)strTemp;	
	strcpy(*dstXML,dst);
	return 0;
}

int CSipMsgProcess::CreateXMLCatalogQuery2(char **dstXML)
{
	CString strTemp;
	strTemp="<?xml version=\"1.0\"?>\r\n";
	strTemp+="<Response>\r\n";
	strTemp+="<QueryResponse>\r\n";
	strTemp+="<Variable>ItemList</Variable>\r\n";
	strTemp+="<Parent>0</Parent>\r\n";	
	strTemp+="<TotalSubNum>45</TotalSubNum>\r\n";
	strTemp+="<TotalOnlineSubNum>1</TotalOnlineSubNum>\r\n";
	strTemp+="<FromIndex>1</FromIndex>\r\n";
	strTemp+="<ToIndex>1</ToIndex>\r\n";
	strTemp+="<SubNum>1</SubNum>\r\n";
	strTemp+="<SubList>\r\n";

	strTemp+="<Item>\r\n";
	strTemp+="<Name>calist</Name>\r\n";
	strTemp+="<Address>135341</Address>\r\n";
	strTemp+="<ResType>0</ResType>\r\n";
	strTemp+="<ResSubType>1</ResSubType>\r\n";
	strTemp+="<Privilege>321345</Privilege>\r\n";
	strTemp+="<Status>1</Status>\r\n";
	strTemp+="<Longitude>23</Longitude>\r\n";
	strTemp+="<Latitude></Latitude>\r\n";
	strTemp+="<Elevation>532</Elevation>\r\n";
	strTemp+="<Roadway>523</Roadway>\r\n";
	strTemp+="<PileNo>245</PileNo>\r\n";
	strTemp+="<AreaNo>531</AreaNo>\r\n";
	strTemp+="<UpdateTime>20130418T120000Z</UpdateTime>\r\n";
	strTemp+="</Item>\r\n";

	strTemp+="<Item>\r\n";
	strTemp+="<Name>list2</Name>\r\n";
	strTemp+="<Address>545434</Address>\r\n";
	strTemp+="<ResType>4</ResType>\r\n";
	strTemp+="<ResSubType>5</ResSubType>\r\n";
	strTemp+="<Privilege>34565</Privilege>\r\n";
	strTemp+="<Status>5</Status>\r\n";
	strTemp+="<Longitude>54</Longitude>\r\n";
	strTemp+="<Latitude>453</Latitude>\r\n";
	strTemp+="<Elevation>35</Elevation>\r\n";
	strTemp+="<Roadway>42</Roadway>\r\n";
	strTemp+="<PileNo>52</PileNo>\r\n";
	strTemp+="<AreaNo>25</AreaNo>\r\n";
	strTemp+="<UpdateTime>20130422T130000Z</UpdateTime>\r\n";
	strTemp+="</Item>\r\n";
	strTemp+="</SubList>\r\n";
	strTemp+="</QueryResponse>\r\n";
	strTemp+="</Response>\r\n";

	char *dst=(LPSTR)(LPCTSTR)strTemp;	
	strcpy(*dstXML,dst);
	return 0;
}

int CSipMsgProcess::CreateXMLDeviceInfQuery(char **dstXML)
{
	CString strTemp;
	strTemp = "<?xml version=\"1.0\"?>\r\n";
	strTemp += "<Response>\r\n";
	strTemp += "<QueryResponse>\r\n";
	strTemp += "<Variable>DeviceInfo</Variable>\r\n";
	strTemp += "<Result>0</Result>\r\n";
	//strTemp += "<Manufacturer>uniview</Manufacturer>\r\n";	 
	//strTemp += "<Model>ECR3316</Model> \r\n";
	//strTemp += "<Firmware>2.1.3.16</Firmware>\r\n";
	//strTemp += "<MaxCamera>16</MaxCamera>\r\n";
	strTemp += "<Result>0</Result>\r\n";
	strTemp += "<Status>0</Result>\r\n";
	strTemp += "</QueryResponse>\r\n";
	strTemp += "</Response>\r\n";

	char *dst=(LPSTR)(LPCTSTR)strTemp;	
	strcpy(*dstXML,dst);
	return 0;
}

int CSipMsgProcess::CreateXMLFlowQuery(char **dstXML)
{
	CString strTemp;
	strTemp="<?xml version=\"1.0\"?>\r\n";
	strTemp+="<Response>\r\n";
	strTemp+="<QueryResponse>\r\n";
	strTemp+="<Variable>BandWidth</Variable>\r\n";
	strTemp+="<Result>0</Result>\r\n";	
	strTemp+="<Manufacturer>uniview</Manufacturer>\r\n";
	strTemp+="<All>256</All>\r\n";
	strTemp+="<Free>240</Free>\r\n";
	strTemp+="<MediaLink>16</MediaLink>\r\n";
	strTemp+="</QueryResponse>\r\n";
	strTemp+="</Response>\r\n";

	char *dst=(LPSTR)(LPCTSTR)strTemp;	
	strcpy(*dstXML,dst);
	return 0;
}

void CSipMsgProcess::SipBYE(char **dst,osip_message_t *srcmsg)
{
	char FromTag[10];
	int RandData;
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(FromTag,str);
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip=new CSipMsgProcess;
	osip_message_set_method(Sip->m_SipMsg.msg,"BYE");	
	osip_message_set_uri(Sip->m_SipMsg.msg,srcmsg->from->url);
	osip_message_set_version(Sip->m_SipMsg.msg,"SIP/2.0");
	osip_call_id_clone(srcmsg->call_id,&Sip->m_SipMsg.msg->call_id);

	osip_from_clone(srcmsg->from,&Sip->m_SipMsg.msg->from);	
	osip_to_clone(srcmsg->to,&Sip->m_SipMsg.msg->to);	
	if (srcmsg->to->gen_params.nb_elt==0 )
	{
		osip_to_set_tag(Sip->m_SipMsg.msg->to,FromTag);
	}
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	osip_message_set_contact(Sip->m_SipMsg.msg,pWnd->contact);
	osip_free(dest);
	//copy via
	osip_message_get_via(srcmsg,0,&Sip->m_SipMsg.via);
	osip_via_to_str(Sip->m_SipMsg.via,&dest);
	osip_message_set_via(Sip->m_SipMsg.msg,dest);
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
	CString st0;
	if (1==i)
	{

		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(Sip->m_SipMsg.msg,dest);
		st0=dest;
		st0="Via: "+st0+"\r\n";		
	}
	else
	{
		st0="";
	}
	osip_free(dest);

	osip_cseq_set_method(Sip->m_SipMsg.cseq,"BYE");
	osip_cseq_set_number(Sip->m_SipMsg.cseq,"2");

	osip_cseq_to_str(Sip->m_SipMsg.cseq,&dest);
	osip_message_set_cseq(Sip->m_SipMsg.msg,dest);
	osip_free(dest);
	osip_message_set_max_forwards(Sip->m_SipMsg.msg,"70");
	osip_message_to_str(Sip->m_SipMsg.msg,&dest,&len);
	memset(*dst,0,MAXBUFSIZE);
	memcpy(*dst,dest,len);
	osip_free(dest);
}