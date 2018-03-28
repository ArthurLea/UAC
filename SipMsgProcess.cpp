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
extern InfoNotify NotifyInfo;
osip_cseq_t *cseq;
//HWND   hnd = ::FindWindow(NULL, _T("UAC"));
//CUACDlg*  pWnd = (CUACDlg*)CWnd::FromHandle(hnd);

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
	//OISP��Դ�ͷ�
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

int CSipMsgProcess::SipParser(char *buffer,int Msglength)
{
	int beginIndex=0;
	int endIndex=0;
	if (OSIP_SUCCESS != osip_message_init(&m_SipMsg.msg))
	{
		AfxMessageBox("OSIP������ʼ��ʧ��",MB_OK|MB_ICONERROR);
		return 1;
	}
	int i = osip_message_parse(m_SipMsg.msg,buffer,Msglength);
	if (i!=OSIP_SUCCESS)
	{	
		AfxMessageBox("SIP��Ϣ��������",MB_OK|MB_ICONERROR);
		return 1;		
	}
	//m_SipMsg.msg->message = buffer;//��ʼ��mes->message,�Ի�ȡexpires��max_forward��
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);	
	//char *Alarmtemp=NULL;
	//if (m_SipMsg.msg->call_id->host==NULL)
	//{		
	//	osip_call_id_to_str(m_SipMsg.msg->call_id,&(Common::nowReservingEventMsg_ArarmCallID));
	//	m_SipMsg.msg->call_id->host="";
	//}
	if (m_SipMsg.msg->call_id->number==NULL)
	{
		m_SipMsg.msg->call_id->number="";
		if (m_SipMsg.msg->call_id->host==NULL)
		{
			m_SipMsg.msg->call_id->host="";
			AfxMessageBox("SIP��Ϣ��Call ID�ֶ�",MB_OK|MB_ICONERROR);
			return 0;
		}		
	}
	//save XML message and parse the XML to the StrTemp
	char *XmlMessage=new char[XMLSIZE];
	memset(XmlMessage,0,XMLSIZE);		
	osip_body_t *XMLbody;
	osip_body_init(&XMLbody);
	osip_message_get_body(m_SipMsg.msg, 0, &XMLbody);
	if (XMLbody != NULL)
	{
		memcpy(XmlMessage, XMLbody->body, strlen(XMLbody->body));
		osip_body_free(XMLbody);
		XMLbody = NULL;
	}
	//parse the XML to the strXML
	string strXML(XmlMessage);
	if (m_SipMsg.msg->sip_method == NULL)//��ֹ�����strcmp����֤���ֿ�ָ��
		m_SipMsg.msg->sip_method = "";
	delete XmlMessage;
	XmlMessage = NULL;
	//�ж��¼�����
//receive register message
	if(strcmp(m_SipMsg.msg->cseq->method,"REGISTER")==0 && strcmp(m_SipMsg.msg->call_id->number, pWnd->RegisterCallID.Num)==0)
	{		
		if (!RegisterSipVerify(pWnd->m_InfoServer,pWnd->m_InfoClient,m_SipMsg.msg,1))
		{
			AfxMessageBox("Register From �� To�ֶ�У�鲻ͨ��",MB_OK|MB_ICONERROR);
			return 0;
		}
		if (m_SipMsg.msg->from->gen_params.nb_elt==0 )
		{
			AfxMessageBox("from must include tag",MB_OK|MB_ICONEXCLAMATION);
			return 0;
		}
		osip_uri_param_t *h;
		osip_uri_param_init(&h);
		osip_from_get_tag(m_SipMsg.msg->from,&h);
		char Tag[10];
		strcpy(Tag,h->gvalue);
		osip_uri_param_free(h);
		if (strcmp(Tag,pWnd->RegisterCallID.Tag)==0)
			m_Type = Register;	
		else
		{
			AfxMessageBox("Tag is error",MB_OK|MB_ICONERROR);
			return 0;
		}
	}
	else if (MSG_IS_NOTIFY(m_SipMsg.msg)) {}
	else if (MSG_IS_INVITE(m_SipMsg.msg))
	{	
		//receive invite message from sever		
		m_Type = Invite;				
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
		pWnd->bACK = TRUE;
		//update log
		pWnd->ShowTestLogData+="<--------  ACK\r\n";		
		SipBYE(&pWnd->byestring,m_SipMsg.msg);
		pWnd->m_Invite.GetDlgItem(IDC_BTN_BYE)->EnableWindow(TRUE);
		return 0;
	}
	else if (MSG_IS_BYE(m_SipMsg.msg))
	{		
		pWnd->bBYE = TRUE;
		pWnd->bACK = FALSE;
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
/*�����Ǹ���"DO"�����XML���� writed by Bsp Lee                          */
/*PTZCommand PresetList FileList VODByRTSP */
/*ItemList DeviceInfo BandWidth EncoderSet TimeSet RealTimeKeepLive*/
/***********************************************************************/
	else if (strcmp(m_SipMsg.msg->sip_method,"DO")==0 && m_SipMsg.msg->status_code == 0)
	{		
		char var[50];
		string::size_type VariableStart;	
		string::size_type VariableEnd;		
		if( ((VariableStart= strXML.find("<Variable>",0)) ==string::npos)
			||(VariableEnd= strXML.find("</Variable>", VariableStart + 1))==string::npos)
		{
			char *dst=new char[MAXBUFSIZE];
			Sip400(&dst,m_SipMsg.msg);
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dst);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);
			delete dst;			
			pWnd->ShowTestLogData+="400 --------> \r\n";
			AfxMessageBox("ȱ��Variable�ֶ�");
			return -1;
		}						
		string temp = strXML.substr(VariableStart+10,VariableEnd-VariableStart-10);
		strcpy(var,temp.c_str());
		temp.erase(0,temp.length());
		osip_body_free(XMLbody);				
		if (strcmp(var,"PTZCommand")==0)
		{
			m_Type = PTZ;
			pWnd->CurStatusID.nSataus=PTZ;
			pWnd->ShowTestLogData=" <---------  DO  \r\n";		
			pWnd->ShowTestLogTitle="PTZ Test";
		}
		else if (strcmp(var,"PresetList")==0 )
		{
			if ((VariableStart = strXML.find("<ReceivePresetNum>", 0)) == string::npos)
			{
				char *dst = new char[MAXBUFSIZE];
				Sip400(&dst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;
				pWnd->ShowTestLogData += "400 --------> \r\n";
				AfxMessageBox("Ԥ��λ��ѯ��ȱ��ReceivePresetNum�ֶ�");
				return 1;
			}
			if ( (VariableEnd = strXML.find("</ReceivePresetNum>",VariableStart+1)) ==string::npos)
			{
				char *dst=new char[MAXBUFSIZE];
				Sip400(&dst,m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;			
				pWnd->ShowTestLogData+="400 --------> \r\n";
				AfxMessageBox("Ԥ��λ��ѯ��ȱ��ReceivePresetNum�ֶ�");
				return 1;
			}
			temp = strXML.substr(VariableStart+18,VariableEnd-VariableStart-18);
			beginIndex=atoi(temp.c_str());
			m_Type=PreBitSet;		
			pWnd->CurStatusID.nSataus=PreBitSet;
			pWnd->ShowTestLogData=" <---------  DO  \r\n";		
			pWnd->ShowTestLogTitle="Ԥ��λ��ѯ";
		}
		else if (strcmp(var,"FileList")==0)
		{
			if ((VariableStart = strXML.find("<BeginTime>", 0)) == string::npos)
			{
				char *dst = new char[MAXBUFSIZE];
				Sip400(&dst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;
				pWnd->ShowTestLogData += "400 --------> \r\n";
				AfxMessageBox("¼���ѯȱ�٣�BeginTime");
				return 1;
			}
			if ((VariableStart = strXML.find("<BeginTime>", 0)) == string::npos)
			{
				char *dst = new char[MAXBUFSIZE];
				Sip400(&dst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;
				pWnd->ShowTestLogData += "400 --------> \r\n";
				AfxMessageBox("¼���ѯȱ�٣�BeginTime");
				return 1;
			}
			if ((VariableStart = strXML.find("<BeginTime>", 0)) == string::npos)
			{
				char *dst = new char[MAXBUFSIZE];
				Sip400(&dst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;
				pWnd->ShowTestLogData += "400 --------> \r\n";
				AfxMessageBox("¼���ѯȱ�٣�BeginTime");
				return 1;
			}
			if ((VariableStart = strXML.find("<EndTime>", 0)) == string::npos)
			{
				char *dst = new char[MAXBUFSIZE];
				Sip400(&dst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;
				pWnd->ShowTestLogData += "400 --------> \r\n";
				AfxMessageBox("¼���ѯȱ�٣�EndTime");
				return 1;
			}
					
			if ((VariableStart = strXML.find("<MaxFileNum>", 0)) == string::npos)
			{
				char *dst = new char[MAXBUFSIZE];
				Sip400(&dst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;
				pWnd->ShowTestLogData += "400 --------> \r\n";
				AfxMessageBox("¼���ѯȱ�٣�MaxFileNum");
				return 1;
			}
			m_Type=HistoryQuery;
			pWnd->ShowTestLogData="<--------- DO\r\n";			
			pWnd->ShowTestLogTitle="History Video Query Test";
		}
		else if (strcmp(var,"VOD")==0)
		{
			m_Type = HistoryPlay;			
			pWnd->ShowTestLogData="<---------- DO\r\n";		
			pWnd->ShowTestLogTitle="Get History Video URL Test";
		}
		else if (strcmp(var,"DeviceInfo")==0)//DeviceInfQuery
		{
			m_Type=DeviceInfQuery;			
			pWnd->ShowTestLogData="<--------- DO\r\n";			
			pWnd->ShowTestLogTitle="Device Query Test";
		}
		else if (strcmp(var,"ItemList")==0)//DeviceCatalogInfQuery
		{
			m_Type = CatalogQuery;			
			pWnd->ShowTestLogData="<--------- DO\r\n";			
			pWnd->ShowTestLogTitle="Device Catalog Query Test";
		}
		else if (strcmp(var,"BandWidth")==0)
		{
			m_Type=FlowQuery;			
			pWnd->ShowTestLogData="<--------- DO\r\n";			
			pWnd->ShowTestLogTitle="Catalog Query Test";
		}
		else if (strcmp(var,"EncoderSet")==0 )
		{
			m_Type = EncoderSet;
			pWnd->CurStatusID.nSataus = EncoderSet;
			pWnd->ShowTestLogData=" <--------  DO \r\n";		
			pWnd->ShowTestLogTitle="Encoder Set Test";
		}
		else if (strcmp(var,"TimeSet")==0 )
		{
			m_Type = TimeSet;
			pWnd->CurStatusID.nSataus = TimeSet;
			pWnd->ShowTestLogData=" <--------  DO \r\n";		
			pWnd->ShowTestLogTitle="Time Set Test";
		}
		else if (strcmp(var,"RealTimeKeepLive")==0 )
		{		
			pWnd->bRealTimeFlag = TRUE;
			char *dst=new char[MAXBUFSIZE];
			Sip200OK(&dst,m_SipMsg.msg);				
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dst);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);
			delete dst;
			return 0;			
		}
		/***********************************************************************/
		/*�����Ǹ���"DO"�����XML���� writed by Bsp Lee                          */
		/*CaptureImage */
		/***********************************************************************/
		else if (strcmp(var, "CaptureImage") == 0)
		{
			m_Type = CaptureImage;
			pWnd->ShowTestLogData = "<---------- DO\r\n";
			pWnd->ShowTestLogTitle = "Get CaptureImage URL Test";
		}
		else
		{
			return 0;
		}
	}
//receive subscribe message from sever
	else if (MSG_IS_SUBSCRIBE(m_SipMsg.msg))//�����б���Ԥ����UAC����
	{
		m_Type = Alarm;		
		pWnd->balarmsubscribe = TRUE;
		//update log
		pWnd->ShowTestLogData="<--------  SUBSCRIBE\r\n";			
		pWnd->ShowTestLogTitle="Alarm Subscribe Test";
	}
//receive keepAlive message
	else if ((strXML.find("KeepAlive",0)!=string::npos)&&(strcmp(m_SipMsg.msg->call_id->number,pWnd->KeepAliveID.Num)==0))
	{
		if ( !SipVerify(pWnd->m_InfoServer,pWnd->m_InfoClient,m_SipMsg.msg,1))
		{
			AfxMessageBox("KeepAlive From or To variable is error",MB_OK|MB_ICONERROR);
			return 0;
		}
		if (m_SipMsg.msg->from->gen_params.nb_elt==0 )
		{
			AfxMessageBox("from must include tag",MB_OK|MB_ICONEXCLAMATION);
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
			return 0;
		}
	}
//receive node message(�豸�ڵ�Ŀ¼���ͣ��¼�֪ͨUAC������Ϣ)
	else if (strcmp(m_SipMsg.msg->call_id->number,pWnd->NodeTypeCallID.Num)==0 )
	{		
		if ( !SipVerify(pWnd->m_InfoServer,pWnd->m_InfoClient,m_SipMsg.msg,1))
		{
			AfxMessageBox("Node Send From or To is error",MB_OK|MB_ICONERROR);
			return 0;
		}
		if (m_SipMsg.msg->from->gen_params.nb_elt==0 )
		{
			AfxMessageBox("from variable must include tag",MB_OK|MB_ICONEXCLAMATION);
			return 0;
		}
		osip_uri_param_t *h;
		osip_uri_param_init(&h);
		osip_from_get_tag(m_SipMsg.msg->from,&h);
		char Tag[10];
		strcpy(Tag,h->gvalue);
		osip_uri_param_free(h);
		if (strcmp(Tag,pWnd->NodeTypeCallID.Tag)==0)
			m_Type = NodeType;	
		else
		{
			AfxMessageBox("Tag is error",MB_OK|MB_ICONERROR);
			return 0;
		}		
	}
//����
	else
	{
		//if (Common::nowReservingEventMsg_ArarmCallID == NULL)
		//{
		//	Common::nowReservingEventMsg_ArarmCallID = new char[100];
		//	strcpy(Common::nowReservingEventMsg_ArarmCallID,m_SipMsg.msg->call_id->number);
		//	strcat(Common::nowReservingEventMsg_ArarmCallID,"@");
		//	//strcat(Common::nowReservingEventMsg_ArarmCallID,m_SipMsg.msg->call_id->host);
		//}
		//string Alarmtemp = Common::nowReservingEventMsg_ArarmCallID;
		//vector<string>::iterator it = find(pWnd->AlarmCallID.begin(), pWnd->AlarmCallID.end(),
		//	Alarmtemp);
		////if (strcmp(Alarmtemp,pWnd->AlarmCallID)==0)
		//if(it != pWnd->AlarmCallID.end())//��ʾ����������Ԥ��Call_ID����ô��ȡ��������ID
		//{
		//	if ( m_SipMsg.msg->status_code==200 )
		//	{
		//		pWnd->ShowTestLogData+="<---------- 200 OK\r\n";
		//		osip_body_t *XMLbody;
		//		osip_body_init(&XMLbody);
		//		int m=10;
		//		m=osip_message_get_body (m_SipMsg.msg, 0, &XMLbody);
		//		osip_body_free(XMLbody);
		//		if ( m==0 )
		//		{
		//			//alarm notify send
		//		}
		//		else
		//		{
		//			pWnd->m_Alarm.GetDlgItem(IDC_BTN_ALARM_NOTIFY)->EnableWindow(TRUE);
		//		}				
		//	}
		//	else if ( m_SipMsg.msg->status_code==400 )
		//	{
		//		pWnd->ShowTestLogData+="<---------- 400\r\n";
		//	}
		//	else
		//	{
		//		AfxMessageBox("alarm other error",MB_OK|MB_ICONERROR);
		//	}
		//	//delete Alarmtemp;
		//}
		//else 
		if (/*strcmp(m_SipMsg.msg->call_id->host,pWnd->TimeSetID.Host)==0 &&*/ 
			strcmp(m_SipMsg.msg->call_id->number,pWnd->TimeSetID.Num)==0 )
		{		
			// receive node message
			if ( !SipVerify(pWnd->m_InfoServer,pWnd->m_InfoClient,m_SipMsg.msg,1))
			{
				AfxMessageBox("Node Send From or To is error",MB_OK|MB_ICONERROR);
				return 0;
			}
			if (m_SipMsg.msg->from->gen_params.nb_elt==0 )
			{
				AfxMessageBox("from variable must include tag",MB_OK|MB_ICONEXCLAMATION);
				return 0;
			}
			osip_uri_param_t *h;
			osip_uri_param_init(&h);
			osip_from_get_tag(m_SipMsg.msg->from,&h);
			char Tag[10];
			strcpy(Tag,h->gvalue);
			osip_uri_param_free(h);
			if (strcmp(Tag,pWnd->TimeSetID.Tag)==0)
				m_Type = TimeGet;	
			else
			{
				AfxMessageBox("Tag is error",MB_OK|MB_ICONERROR);
				return 0;
			}		
		}
	}
	switch (m_Type)
	{
	case Register://ע��
		{	
			cseq=m_SipMsg.msg->cseq;
			if ( m_SipMsg.msg->status_code==200)
			{
				pWnd->ShowRecvData("\t\t-----ע��ɹ�-----\r\n");
				pWnd->ShowTestLogData += "<------------ 200 OK\r\n";
				//ע��ɹ���������
				pWnd->bKeepAlive = TRUE;
				//osip_header_t *timeIntervalTemp = NULL;
				//osip_message_get_expires(m_SipMsg.msg, 0, &timeIntervalTemp);
				//char * expiresName = timeIntervalTemp->hname;
				//int timeInterval = atoi(timeIntervalTemp->hvalue);
				int timeInterval = atoi(Common::EXPIRES_VALUE) / 3 * 1000;
				pWnd->SetTimer(1, timeInterval, NULL);//�ɹ�����Ҫ����������Ϣ����,��ʱ��־Ϊ1

				char *dst=new char[XMLSIZE];				
				char *dstNodeMsg=new char[MAXBUFSIZE];

				//���ݲ����ĵ�Ҫ��ע��ɹ���������豸�ڵ���Ϣ��Ȼ���͸�����Ŀ��������Ԫ
				XmlNodeCreate(&dst);
				SipNodeXmlMsg(&dstNodeMsg,pWnd->m_InfoServer,pWnd->m_InfoClient,dst,m_SipMsg.msg);				
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstNodeMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				pWnd->ShowSendData(dstNodeMsg);

				Common::DEVICECATALOG_COUNT = 2;//��һ�η����豸Ŀ¼�ṹ
				delete dst;					
				delete dstNodeMsg;				
				//update log
				pWnd->ShowTestLogData+="NOTIFY---------->\r\n";	
				pWnd->EnableWindow(IDC_BTN_RESULT,TRUE);	
				pWnd->m_PSTVSetTime.GetDlgItem(IDC_BUTTON_PSTVTIME)->EnableWindow(TRUE);
			}
			else if(m_SipMsg.msg->status_code==400)
			{	
				pWnd->ShowRecvData("\t\t-----ע��ʧ�ܻ�ʱ----\r\n");
				pWnd->ShowTestLogData+="<--------  400\r\n";
				pWnd->bKeepAlive=FALSE;
				pWnd->KillTimer(3);	
				pWnd->EnableWindow(IDC_BTN_SIP_REGISTER,TRUE);
				pWnd->EnableWindow(IDC_BTN_RESULT,FALSE);							
			}
			else if(m_SipMsg.msg->status_code==401)
			{	
				pWnd->ShowRecvData("\t\t-----ע��ʧ��(û��Я��Ȩǩ��Ϣ)----\r\n");
				pWnd->ShowTestLogData+="<--------  401\r\n";
// 				pWnd->bKeepAlive=FALSE;
// 				pWnd->KillTimer(3);	
// 				pWnd->EnableWindow(IDC_BTN_SIP_REGISTER,TRUE);
// 				pWnd->EnableWindow(IDC_BTN_RESULT,FALSE);
				string strbuf=buffer;
				int index=strbuf.find("realm");
				if (index==string::npos)
				{
					AfxMessageBox("ȱ��realm��Ϣ��",MB_OK|MB_ICONERROR);
					return 0;
				}
				int index1=strbuf.find('"',index);
				int index2=strbuf.find('"',index1+1);
				g_authInfo.realm=strbuf.substr(index1+1,index2-index1-1);

				index=strbuf.find("nonce");
				if (index==string::npos)
				{
					AfxMessageBox("ȱ��nonce��Ϣ��",MB_OK|MB_ICONERROR);
					return 0;
				}
				index1=strbuf.find('"',index);
				index2=strbuf.find('"',index1+1);
				g_authInfo.nonce=strbuf.substr(index1+1,index2-index1-1);

				index=strbuf.find("opaque");
				if (index==string::npos)
				{
					AfxMessageBox("ȱ��opaque��Ϣ��",MB_OK|MB_ICONERROR);
					return 0;
				}
				index1=strbuf.find('"',index);
				index2=strbuf.find('"',index1+1);
				g_authInfo.opaque=strbuf.substr(index1+1,index2-index1-1);
// 				index=strbuf.find("qop");
// 				if (index==string::npos)
// 				{
// 					AfxMessageBox("ȱ��qop��Ϣ��",MB_OK|MB_ICONERROR);
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
				return 1;
			}
		}
		break;
	case NodeType://�豸Ŀ¼��Ϣ���¼�����֪ͨ��
		{
			if (m_SipMsg.msg->status_code==200)
			{
				if (strXML.find("<Variable>", 0) == string::npos)
				{
					AfxMessageBox("����ȱ��Variable�ֶΣ�", MB_OK | MB_ICONEXCLAMATION);
					return 1;
				}
				if (strXML.find("</Variable>", 0) == string::npos)
				{
					AfxMessageBox("����ȱ��/Variable�ֶΣ�", MB_OK | MB_ICONEXCLAMATION);
					return 1;
				}
				//�豸Ŀ¼����ϢUAS����
				if (strXML.find("Catalog", 0) != string::npos)
				{
					pWnd->ShowRecvData("\t\t-----�豸�ڵ���Ϣ���ͳɹ�-----\r\n");
					pWnd->ShowTestLogData += "<--------- 200 OK\r\n";

					char *dst = new char[XMLSIZE];
					char *dstNodeMsg = new char[MAXBUFSIZE];
					/*
					if (Common::DEVICECATALOG_COUNT == 2)//�ڶ������ͣ��������µ�ģ�������Ϣ����
					{
						XmlNodeCreate1(&dst);
						SipNodeXmlMsg(&dstNodeMsg, pWnd->m_InfoServer, pWnd->m_InfoClient, dst, m_SipMsg.msg);
						UA_Msg uac_sendtemp;
						strcpy(uac_sendtemp.data, dstNodeMsg);
						EnterCriticalSection(&g_uac);
						uac_sendqueue.push(uac_sendtemp);
						LeaveCriticalSection(&g_uac);

						Common::DEVICECATALOG_COUNT = 3;
						delete dst;
						delete dstNodeMsg;
					}
					else if (Common::DEVICECATALOG_COUNT == 3)//���������ͣ�DVR�������ӵ�ģ�������Ϣ����
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
					*/
				}
				//�¼�����֪ͨ����ϢUAS����
				if (strXML.find("AlarmNotify", 0) != string::npos)
				{
					//����ֻ����֪ͨ�Ƿ�ɹ��Ĳ���
					pWnd->m_Alarm.GetDlgItem(IDC_BTN_ALARM_CANCEL)->EnableWindow(true);
					pWnd->ShowRecvData("\t\t-----�¼�����֪ͨ�ɹ�-----\r\n");
					pWnd->ShowTestLogData += "<--------- 200 OK\r\n";
				}
			} 
			else if(m_SipMsg.msg->status_code==400)
			{
				pWnd->ShowRecvData("\t\t-----�豸�ڵ���Ϣ����ʧ��-----\r\n");
				pWnd->ShowTestLogData+="<--------- 400\r\n";			
				pWnd->KillTimer(3);
			}
			else
			{
				//receive other message
				return 1;
			}
		}
		break;
	case Invite:
		{
			pWnd->bACK = FALSE;
			pWnd->bBYE = FALSE;

			char *dst=new char[XMLSIZE];
			char *dstInviteMsg=new char[MAXBUFSIZE];
			char *XMLTemp = new char[MAXBUFSIZE];
			strcpy(XMLTemp, strXML.c_str());
			if( XmlInviteCreate(&dst, XMLTemp) )
			{	//100 try
				char *tryDst = new char[MAXBUFSIZE];
				Sip100Try(&tryDst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, tryDst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete tryDst;
				pWnd->ShowTestLogData += "trying 100 ---------> \r\n";
				for (int i = 10000; i > 0; i--) { 0 == 0; }
				SipInvite200Xml(&dstInviteMsg,m_SipMsg.msg,dst);
				strcpy(uac_sendtemp.data,dstInviteMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				pWnd->ShowTestLogData+="200 OK --------> \r\n";			
			}
			else
			{
				SipInvite400(&dstInviteMsg,m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstInviteMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				pWnd->ShowTestLogData+="400 --------> \r\n";
			}
			delete dst;
			delete dstInviteMsg;
			delete XMLTemp;
		}
		break;
	case CANCEL:
		{
			pWnd->bACK = TRUE;
			pWnd->bBYE = TRUE;
			
			//sleep time			
			char *dst=new char[XMLSIZE];
			char *dstInviteMsg=new char[MAXBUFSIZE];
			SipCancel200Xml(&dstInviteMsg,m_SipMsg.msg);
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dstInviteMsg);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);
			delete dst;		
			delete dstInviteMsg;			
			pWnd->ShowTestLogData+="200 OK --------> \r\n";		

		}
		break;
	case PTZ:
		{
			char *dst=new char[XMLSIZE];
			char *dstPTZMsg=new char[MAXBUFSIZE];
			char *XMLTemp = new char[MAXBUFSIZE];
			strcpy(XMLTemp, strXML.c_str());
			if( XmlPTZCreate(&dst, XMLTemp) )
			{
				Sip200Xml(&dstPTZMsg,m_SipMsg.msg,dst);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstPTZMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				pWnd->ShowTestLogData+="200  OK ------->\r\n";			
			}
			else
			{
				Sip400(&dstPTZMsg,m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstPTZMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				pWnd->ShowTestLogData+="400  ------->\r\n";
			}
			delete dst;
			delete dstPTZMsg;
			delete XMLTemp;
		}
		break;
	case PreBitSet:
		{					
			char *xml=new char[XMLSIZE];			
			/*CreateXMLVideoQuery(&xml);
			if (endIndex>PresetInfoList.size()/4)
			{
				endIndex=PresetInfoList.size()/4;
			}
			if(endIndex-beginIndex<5)CreateXMLptzPreBitQuery_c(&xml,beginIndex,endIndex);
			else CreateXMLptzPreBitQuery_c(&xml,beginIndex,beginIndex+4);
			
			char*xml=(LPSTR)(LPCTSTR)strTemp;	
			begindex����receivepresetnum��ʼ��0;
			*/
			if ((beginIndex + 6) > PresetInfoList.size() / 4)
				CreateXMLptzPreBitQuery_c(&xml, beginIndex, PresetInfoList.size() / 4);
			else
				CreateXMLptzPreBitQuery_c(&xml, beginIndex+1, beginIndex + 5);
			char *dstMsg=new char[MAXBUFSIZE];
			Sip200Xml(&dstMsg,m_SipMsg.msg,xml);
			UA_Msg uac_sendtemp;
			strcpy(uac_sendtemp.data,dstMsg);
			EnterCriticalSection(&g_uac);
			uac_sendqueue.push(uac_sendtemp);
			LeaveCriticalSection(&g_uac);
			delete dstMsg;
			pWnd->ShowTestLogData+="200  OK ------->\r\n";	
		}
		break;
	case HistoryQuery:
		{
			char *xml=new char[XMLSIZE];		

			CTime beginTime;
			CTime endTime;
			int MaxFileNum;
			int nYear, nMonth, nDate, nHour, nMin, nSec;
			string tem;
			string temcreatetime;
			string temendtime;
			int fromidex=0;
			int toindex=0;
			int variableStart = strXML.find("<BeginTime>", 0);
			int variableEnd = strXML.find("</BeginTime>", 0);
			string begintime = strXML.substr(variableStart + 11, variableEnd - variableStart - 11);
			if ((variableStart == string::npos) || (variableEnd == string::npos)
				|| (strcmp(begintime.c_str(), "") == 0))
			{
				char *dst = new char[MAXBUFSIZE];
				Sip400(&dst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;
				pWnd->ShowTestLogData += "400 --------> \r\n";
				AfxMessageBox("ȱ��BeginTime�ֶλ���BeginTime�ֶ�û����Ϣ...");
				return 1;
			}
			else
			{
				sscanf(begintime.c_str(), "%d-%d-%dT%d:%d:%dZ", &nYear, &nMonth, &nDate, &nHour, &nMin, &nSec);;
				
				CTime begin(nYear, nMonth, nDate, nHour, nMin, nSec);
				beginTime = begin;
			}


			variableStart = strXML.find("<EndTime>", 0);
			variableEnd = strXML.find("</EndTime>", 0);
			string endtime = strXML.substr(variableStart + 9, variableEnd - variableStart - 9 );
			if ((variableStart == string::npos) || (variableEnd == string::npos)
				|| (strcmp(endtime.c_str(), "") == 0))
			{
				char *dst = new char[MAXBUFSIZE];
				Sip400(&dst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;
				pWnd->ShowTestLogData += "400 --------> \r\n";
				AfxMessageBox("ȱ��endtime�ֶλ���EndTime�ֶ�û����Ϣ...");
				return 1;
			}
			else
			{
				sscanf(endtime.c_str(), "%d-%d-%dT%d:%d:%dZ", &nYear, &nMonth, &nDate, &nHour, &nMin, &nSec);;

				CTime end(nYear, nMonth, nDate, nHour, nMin, nSec);
				endTime = end;

			}

			variableStart = strXML.find("<MaxFileNum>", 0);
			variableEnd = strXML.find("</MaxFileNum>", 0);
			string maxFileNum = strXML.substr(variableStart + 12, variableEnd - variableStart - 12);
			if ((variableStart == string::npos) || (variableEnd == string::npos)
				|| (strcmp(maxFileNum.c_str(), "") == 0))
			{
				char *dst = new char[MAXBUFSIZE];
				Sip400(&dst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;
				pWnd->ShowTestLogData += "400 --------> \r\n";
				AfxMessageBox("ȱ��maxFileNum�ֶλ���maxFileNum�ֶ�û����Ϣ...");
				return 1;
			}
			else
			{
				MaxFileNum = atoi(maxFileNum.c_str());
			}

			//CreateXMLVideoQuery(&xml);
			/*
			if (endIndex*6>HistoryVideoList.size())
			{
				endIndex=HistoryVideoList.size()/6;
			}
			if(endIndex-beginIndex<5)CreateXMLVideoQuery_c(&xml,beginIndex,endIndex);
			else CreateXMLVideoQuery_c(&xml,beginIndex,beginIndex+4);
			*/

			for (int i = 2; i < HistoryVideoList.size(); i +=6)
			{
				//��ȡ�б���ÿһ��ʱ�䣬�봫���ʱ�����Ƚϣ��õ���Ҫ���͵���ʷ���б�
				tem = HistoryVideoList[i];
				variableStart = tem.find("<CreationTime>", 0);
				variableEnd = tem.find("</CreationTime>", 0);
				temcreatetime = tem.substr(variableStart + 14, variableEnd - variableStart - 14);
				sscanf(temcreatetime.c_str(), "%d - %d - %dT%d:%d : %dZ", &nYear, &nMonth, &nDate, &nHour, &nMin, &nSec);
				CTime tempbeginTime(nYear, nMonth, nDate, nHour, nMin, nSec);
				if (beginTime > tempbeginTime)
				{
					fromidex++;
				}
				//�ֱ�õ���ʼλ��
				tem = HistoryVideoList[i+1];
				variableStart = tem.find("<LastWriteTime>", 0);
				variableEnd = tem.find("</LastWriteTime>", 0);
				temendtime = tem.substr(variableStart + 15, variableEnd - variableStart - 15);	
				sscanf(temendtime.c_str(), "%d - %d - %dT%d:%d : %dZ", &nYear, &nMonth, &nDate, &nHour, &nMin, &nSec);
				CTime tempendTime(nYear, nMonth, nDate, nHour, nMin, nSec);
				if (endTime > tempendTime)
				{
					toindex++;
				}

			}
/*			
			if (MaxFileNum * 6>HistoryVideoList.size())
			{
				MaxFileNum = HistoryVideoList.size() / 6;
			}
*/

			if (toindex - fromidex<MaxFileNum)
				CreateXMLVideoQuery_c(&xml, fromidex, toindex);
			else 
				CreateXMLVideoQuery_c(&xml, fromidex, fromidex + MaxFileNum);
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
	case CatalogQuery://Ŀ¼�ڵ��ѯ
		{
			string st=buffer;
			int index = st.find("<Address>",0);
			if (index==string::npos)
			{
				AfxMessageBox("Ŀ¼��ѯ��ȱ��Address�ֶΣ�",MB_OK|MB_ICONERROR);
			}
			int index2=st.find("</Address>");
			if (index2==string::npos)
			{
				AfxMessageBox("Ŀ¼��ѯ��ȱ��/Address�ֶΣ�",MB_OK|MB_ICONERROR);
			}
			string strT=st.substr(index+9,index2-index-9);
			if (strT.compare("")==0)
			{
				AfxMessageBox("Ŀ¼��ѯ��Address�ֶ�Ϊ�գ�",MB_OK|MB_ICONERROR);
			}
			//252000001199000001 == pWnd->m_InfoClient.UserAddress
			if (strT.compare("252000001199000001")==0)//252000001199000001Ŀ¼�ڵ�
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
			if ((strT.compare("252000001201001001")==0) || (strT.compare("252000001301001001")==0))//252000001201001001 ||��252000001301001001�ӽڵ�
			{
				char *xml=new char[XMLSIZE];
				CreateXMLCatalogQueryNote(&xml);
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
	case DeviceInfQuery://�豸��Ϣ��ѯ
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
	case FlowQuery://������ѯ
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
			strTemp+="<QueryResponse>\r\n";
			strTemp+="<Variable>VOD</Variable>\r\n";
			strTemp+="<Result>0</Result>\r\n";
			strTemp+="<Bitrate>100</Bitrate>\r\n";
			//rtsp://192.168.1.7:8554/filename.264
			// rtsp://192.168.1.7:8554/<filename>
			strTemp+="<Playurl>rtsp://"+pWnd->m_InfoClient.IP+":"+/*pWnd->TCP_Port*/"8554/060111410001-060110600001-100316183000.ts"+"</Playurl>\r\n";
			strTemp+="</QueryResponse>\r\n";
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
	case EncoderSet://��������
		{
			char *dst=new char[XMLSIZE];
			char *dstEncoderSetMsg=new char[MAXBUFSIZE];
			char *XMLTemp = new char[MAXBUFSIZE];
			strcpy(XMLTemp, strXML.c_str());
			if( XmlEncoderSetCreate(&dst, XMLTemp) )
			{
				//UAC�˱������������ò�����ʾpWnd->m_CoderSet.m_EncoderParam
				ShowEncoderParam(buffer);
				Sip200Xml(&dstEncoderSetMsg,m_SipMsg.msg,dst);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstEncoderSetMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//update log
				pWnd->ShowTestLogData+="200  OK -------->\r\n";	
			}
			else
			{
				Sip400(&dstEncoderSetMsg,m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstEncoderSetMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//update log
				pWnd->ShowTestLogData+="400  -------->\r\n";
			}
			delete dst;
			delete dstEncoderSetMsg;
			delete XMLTemp;
		}
		break;
	case TimeGet:
		{
			if (m_SipMsg.msg->status_code==200)
			{
				int timeStart = strXML.find("<Time>", 0);;
				int timeEnd = timeEnd = strXML.find("</Time>", 0);
				string time = strXML.substr(timeStart + 6, timeEnd - timeStart - 6);
				pWnd->m_PSTVSetTime.GetDlgItem(IDC_EDIT_PSTVTIME)->SetWindowTextA(time.c_str());
				
				pWnd->ShowRecvData("\t\t-----ʱ������ɹ�-----\r\n");
				pWnd->ShowTestLogData+="<----------200  OK \r\n";
			}
			else if (m_SipMsg.msg->status_code==400)
			{
				//receive 400 ok message
				pWnd->ShowRecvData("\t----ʱ�����ʧ��----\r\n");	
				//update log				
				pWnd->ShowTestLogData+=" <---------  400\r\n";
			}
			else
			{
				//receive other message
				return 1;
			}
		}
		break;
	case TimeSet:
		{
			//UAC����ʾ��UAS�˵õ���ʱ��
			int timeStart = strXML.find("<Time>", 0);;
			int timeEnd = strXML.find("</Time>", 0);
			string time  = strXML.substr(timeStart + 6, timeEnd - timeStart - 6);
			if ((timeStart == string::npos) || (timeEnd == string::npos) 
				||(strcmp(time.c_str(),"")==0))
			{
				char *dst = new char[MAXBUFSIZE];
				Sip400(&dst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;
				pWnd->ShowTestLogData += "400 --------> \r\n";
				AfxMessageBox("ȱ��Time�ֶλ���Time�ֶ�û����Ϣ...");
				return 1;
			}
			else
			{
				pWnd->m_PSTVSetTime.GetDlgItem(IDC_EDIT_NGTVTIME)->SetWindowTextA(time.c_str());
				//���лش�
				CString strTemp;
				strTemp = "<?xml version=\"1.0\"?>\r\n";
				strTemp += "<Response>\r\n";
				strTemp += "<ControlResponse>\r\n";
				strTemp += "<Variable>TimeSet</Variable>\r\n";
				strTemp += "<Result>0</Result>\r\n";
				strTemp += "<Privilege>0100100001</Privilege>\r\n";//���豸������Ȩ����
				strTemp += "</ControlResponse>\r\n";
				strTemp += "</Response>\r\n";
				char*xml = (LPSTR)(LPCTSTR)strTemp;
				char *dstMsg = new char[MAXBUFSIZE];
				Sip200Xml(&dstMsg, m_SipMsg.msg, xml);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dstMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dstMsg;
				pWnd->ShowTestLogData += "200  OK ------->\r\n";
			}
		}
		break;
	case Alarm://UAS�ı���Ԥ��������Ϣ
		{
			char *dst=new char[XMLSIZE];
			char *dstAlarmMsg=new char[MAXBUFSIZE];
			char *XMLTemp = new char[MAXBUFSIZE];
			strcpy(XMLTemp, strXML.c_str());
			if( XmlAlarmCreate(&dst, XMLTemp))//��ʼ������Ϣ
			{
				Sip200Xml(&dstAlarmMsg,m_SipMsg.msg,dst);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstAlarmMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				pWnd->ShowTestLogData+="200  OK ---------->\r\n";	

				//�жϵ�ǰ��(pWnd->AlarmCallID)���Ƿ������ҪԤ������ȡ����Ԥ��Call_ID
				vector<string>::iterator it = find(pWnd->AlarmCallID.begin(), pWnd->AlarmCallID.end(),
					m_SipMsg.msg->call_id->number);
				if (it != pWnd->AlarmCallID.end())//��ʾ����������Ԥ��Call_ID����ô��ȡ��������ID
												  //��ʾȡ��������Ԥ���¼������سɹ�
				{
					CString CALLID = m_SipMsg.msg->call_id->number;
					pWnd->ShowTestLogData += "�ɹ�ȡ��CallIDΪ"+ CALLID +"�ı����¼�" + "---------->\r\n";
					//��pWnd->AlarmCallID��ɾ�����CALLID
					pWnd->AlarmCallID.erase(it);
					//pop XmlAlarmCreate�д洢��m_InfoAlarm
					pWnd->m_InfoAlarm.pop_back();
					//��ɾ��CALLIDΪm_SipMsg.msg->call_id->number��m_InfoAlarm
					for (vector<InfoAlarm>::iterator iter_Info = pWnd->m_InfoAlarm.begin();
						iter_Info != pWnd->m_InfoAlarm.end(); iter_Info++)
					{
						InfoAlarm infoAlarm = (InfoAlarm)(*iter_Info);
						char *needEarseCallID = new char[20];
						strcpy(needEarseCallID, infoAlarm.CallID.c_str());
						if (strcmp(needEarseCallID, m_SipMsg.msg->call_id->number) == 0)
						{
							iter_Info = pWnd->m_InfoAlarm.erase(iter_Info);
							delete needEarseCallID;
							break;
						}
					}

				}
				else//����Ļ��ǽ��б����¼�Ԥ�������Ҵ����Ӧ��CALLID
				{
					Common::FLAG_Notify_EventReserve = true;
					//����CALLID�Ĵ洢
					pWnd->AlarmCallID.push_back(m_SipMsg.msg->call_id->number);
					int count = pWnd->m_InfoAlarm.size();
					pWnd->m_InfoAlarm[count-1].CallID = m_SipMsg.msg->call_id->number;

					//sleep time				
					char *alarmnotify = new char[MAXBUFSIZE];
					//200 OK֮���NOTIFY��Ϣ UAC -> UAS
					SipAlarmSubscribeNotify(&alarmnotify, pWnd->m_InfoServer, pWnd->m_InfoClient, m_SipMsg.msg);
					UA_Msg uac_sendtemp1;
					strcpy(uac_sendtemp1.data, alarmnotify);
					EnterCriticalSection(&g_uac);
					uac_sendqueue.push(uac_sendtemp1);
					LeaveCriticalSection(&g_uac);
					delete alarmnotify;
					pWnd->balarmsubscribe = FALSE;
					pWnd->ShowTestLogData += "NOTIFY ---------->\r\n";
				}
			}
			else//XMLû��׼���ã�����400 
			{
				Sip400(&dstAlarmMsg,m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data,dstAlarmMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				//update log
				pWnd->ShowTestLogData+="400  ---------->\r\n";
			}
			delete dst;
			delete dstAlarmMsg;
			delete XMLTemp;
		}
		break;
	case CaptureImage:
		{
			//UAS����Ҫ��ȡץͼ��Ϣ
			int capTyStart = strXML.find("<CaptureType>", 0);;
			int capTyEnd = strXML.find("</CaptureType>", 0);
			string capTy = strXML.substr(capTyStart + 13, capTyEnd - capTyStart - 13);
			int pvlgStart = strXML.find("<Privilege>", 0);;
			int pvlgEnd = strXML.find("</Privilege>", 0); 
			string privilege = strXML.substr(pvlgStart + 11, pvlgEnd - pvlgStart - 11);
			if ((capTyStart == string::npos) || (capTyEnd == string::npos)
				|| (strcmp(capTy.c_str(), "") == 0))
			{
				char *dst = new char[MAXBUFSIZE];
				Sip400(&dst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;
				pWnd->ShowTestLogData += "400 --------> \r\n";
				AfxMessageBox("ȱ��CaptureType�ֶλ���CaptureType�ֶ�û����Ϣ...");
				return -1;
			}
			else if ((pvlgStart == string::npos) || (pvlgEnd == string::npos)
				|| (strcmp(privilege.c_str(), "") == 0))
			{
				char *dst = new char[MAXBUFSIZE];
				Sip400(&dst, m_SipMsg.msg);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dst);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dst;
				pWnd->ShowTestLogData += "400 --------> \r\n";
				AfxMessageBox("ȱ��Privilege�ֶλ���Privilege�ֶ�û����Ϣ...");
				return -1;
			}
			else
			{
				//���лش�
				string strURL;
				CString url;
				pWnd->m_PSTVSetTime.GetDlgItem(IDC_EDIT_URL)->GetWindowTextA(url);
				string tempUrl = url;
				int indexUrl = tempUrl.find("/", 0);
				tempUrl = tempUrl.substr(indexUrl);
				if (strcmp(capTy.c_str(), "0") == 0)//ץȡʵʱ����I֡
				{
					//strURL = "http://192.168.9.240/11/123456.jpg";
					char ch[1024] = "http:";
					strcat(ch, tempUrl.c_str());
					strURL = ch;
				}
				else if (strcmp(capTy.c_str(), "1") == 0)//IPCֱ��ץͼ
				{
					//strURL = "ftp://192.168.9.240/11/1.jpg";
					char ch[1024] = "ftp:";
					strcat(ch, tempUrl.c_str());
					strURL = ch;
				}
				CString URL = strURL.c_str();
				CString strTemp;
				strTemp = "<?xml version=\"1.0\"?>\r\n";
				strTemp += "<Response>\r\n";
				strTemp += "<ControlResponse>\r\n";
				strTemp += "<Variable>CaptureImage</Variable>\r\n";
				strTemp += "<Result>0</Result>\r\n";
				strTemp += "<URL>"+URL+"</URL>\r\n";
				strTemp += "</ControlResponse>\r\n";
				strTemp += "</Response>\r\n";
				char*xml = (LPSTR)(LPCTSTR)strTemp;
				char *dstMsg = new char[MAXBUFSIZE];
				Sip200Xml(&dstMsg, m_SipMsg.msg, xml);
				UA_Msg uac_sendtemp;
				strcpy(uac_sendtemp.data, dstMsg);
				EnterCriticalSection(&g_uac);
				uac_sendqueue.push(uac_sendtemp);
				LeaveCriticalSection(&g_uac);
				delete dstMsg;
				pWnd->ShowTestLogData += "200  OK ------->\r\n";
			}
		}
		break;
	default:
		break;
	}
	return 0;
}

int CSipMsgProcess::SipRegisterCreate(char **strRegister,InfoServer m_InfoServer,InfoClient m_InfoClient)
{	
	char FromTag[10];
	char CallID[10];
	//Զ��������Ϣ
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//����������Ϣ
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
	/*char branch[20] = "z9hG4bK";
	for (int i = 0; i < 8; i++)
	{
		RandData = rand() % 10;
		branch[i + 7] = RandData + '0';
	}
// 	itoa(RandData,sdtr,16);
	osip_via_set_branch(SipRegister->m_SipMsg.via,branch);//�����
*/	
	osip_via_set_host(SipRegister->m_SipMsg.via,srcIP);

	//osip_call_id_set_host(SipRegister->m_SipMsg.callid, srcIP);
	osip_call_id_set_number(SipRegister->m_SipMsg.callid,CallID);//�����

	//������ע�����Ϣ��CallID��Ϣ
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	strcpy(pWnd->RegisterCallID.Host,srcIP);
	strcpy(pWnd->RegisterCallID.Num,CallID);

	osip_from_set_displayname(SipRegister->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipRegister->m_SipMsg.from,FromTag);//�����
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
	//Զ��������Ϣ
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//����������Ϣ
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
	//osip_via_set_branch(SipRegister->m_SipMsg.via,"z9hG4bK--22bd7222");//�����
// 	RandData=rand();	
// 	char sdtr[10];	
// 	char branch[20];
// 	itoa(RandData,sdtr,16);
// 	strcpy(branch,"z9hG4bK--");
// 	strcat(branch,sdtr);
// 	osip_via_set_branch(SipRegister->m_SipMsg.via,branch);//�����
	osip_via_set_host(SipRegister->m_SipMsg.via,srcIP);

	//osip_call_id_set_host(SipRegister->m_SipMsg.callid, srcIP);
	osip_call_id_set_number(SipRegister->m_SipMsg.callid,CallID);//�����
	//������ע�����Ϣ��CallID��Ϣ
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	strcpy(pWnd->RegisterCallID.Host,srcIP);
	strcpy(pWnd->RegisterCallID.Num,CallID);

	osip_from_set_displayname(SipRegister->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipRegister->m_SipMsg.from,FromTag);//�����
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
	HWND   hnd = ::FindWindow(NULL, _T("UAC"));
	CUACDlg*  pWnd = (CUACDlg*)CWnd::FromHandle(hnd);
	CString strTemp;
	/*strTemp ="<?xml version=\"1.0\"?>\r\n";
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
	strTemp += "<Manufacturer>��������</Manufacturer>\r\n";
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
	strTemp += "<Manufacturer>��������</Manufacturer>\r\n";
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
	//<��·���ƺ�λ��׮�ſɲ���>
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
	strTemp += "<Manufacturer>��������</Manufacturer>\r\n";
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

	*/
#pragma region NODEXML
	strTemp = "<?xml version=\"1.0\"?>\r\n";
	strTemp += "<Action>\r\n";
	strTemp += "<Variable>Catalog</Variable>\r\n";
	strTemp += "<Parent>" + pWnd->m_InfoClient.UserAddress + "</Parent>\r\n";
	//strTemp+="<TotalSubNum>10</TotalSubNum>\r\n";
	//strTemp+="<TotalOnlineSubNum>10</TotalOnlineSubNum>\r\n";
	strTemp += "<SubNum>2</SubNum>\r\n";
	strTemp += "<SubList>\r\n";
	strTemp += "<Item>\r\n";
	strTemp += "<Name>CAM-0001</Name>\r\n";
	strTemp += "<Address>011051430001</Address>\r\n";
	//strTemp += "<Privilege>%00%80</Privilege>\r\n";
	strTemp += "<Privilege>20</Privilege>\r\n";
	strTemp+="<ResType>1</ResType>\r\n";
	//	strTemp+="<ResSubType>0</ResSubType>\r\n";//restypeΪ1ʱ������
	//strTemp+="<SeriesNumber>000000000123</SeriesNumber>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>10</Longitude>\r\n";
	strTemp += "<Latitude>10</Latitude>\r\n";
	strTemp += "<Elevation>10</Elevation>\r\n";
	//	strTemp += "<DecoderTag>H3C< / DecoderTag>\r\n";
	strTemp += "<SeriesNumber>0001</SeriesNumber>\r\n";
	strTemp += "<Roadway>011</Roadway>\r\n";
	strTemp += "<PileNo>10</PileNo>\r\n";
	strTemp += "<SubNum>0</SubNum>\r\n";

	//	strTemp+="<AreaNo>1</AreaNo>\r\n";
	strTemp += "<OperateType>ADD</OperateType>\r\n";
	//strTemp+="<UpdateTime>20140901T133050Z</UpdateTime>\r\n";
	strTemp += "</Item>\r\n";
	pWnd->m_Invite.m_address.AddString("CAM-0001");
	pWnd->m_Invite.address.push_back("011061430001");


	strTemp += "<Item>\r\n";
	strTemp += "<Name>IPC-01</Name>\r\n";
	//NotifyInfo.Devices[0].Name = "IPC-01";
	strTemp += "<Address>011051450001</Address>\r\n";
	//	strTemp += "<Privilege>%02</Privilege>\r\n";//���������Ŀ��ƹ��ܣ����ݰ汾������
	strTemp += "<Privilege>20</Privilege>\r\n";//��������û������ͱ���
											   //strTemp+="<ResType>1</ResType>\r\n";
											   //strTemp+="<ResSubType>2</ResSubType>\r\n";
											   //strTemp+="<SeriesNumber>000000000323</SeriesNumber>\r\n"
	strTemp += "<SeriesNumber>0001</SeriesNumber>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>20</Longitude>\r\n";
	strTemp += "<Latitude>20</Latitude>\r\n";
	strTemp += "<Elevation>20</Elevation>\r\n";
	//	strTemp += "<SubNum>0</SubNum>\r\n";
	strTemp += "<DecoderTag>H3C</DecoderTag>\r\n";
	strTemp += "<Roadway>011</Roadway>\r\n";
	strTemp += "<PileNo>20</PileNo>\r\n";
	//strTemp+="<AreaNo>1</AreaNo>\r\n";
	strTemp += "<OperateType>ADD</OperateType>\r\n";
	//	strTemp+="<UpdateTime>20140902T103036Z</UpdateTime>\r\n";	
	strTemp += "</Item>\r\n";

	pWnd->m_Invite.m_address.AddString("IPC-01");
	pWnd->m_Invite.address.push_back("011051450001");

//	pWnd->m_Alarm.m_selAddress.AddString("IPC-01");
//	pWnd->m_Alarm.address.push_back("011061450001");
	strTemp += "</SubList>\r\n";
	strTemp += "</Action>\r\n";
#pragma endregion
	char *str = (LPSTR)(LPCTSTR)strTemp;
	strcpy(*strNodeXml, str);
	NodeAnylse(NotifyInfo, str);
	
	/*
	pWnd->m_Invite.m_selAddress.ResetContent();
	pWnd->m_PTZ.m_selAddress.ResetContent();
	pWnd->m_VideoQuery.m_selAddress.ResetContent();
	pWnd->m_Alarm.m_selAddress.ResetContent();
	pWnd->m_DeviceInfQuery.m_selAddress.ResetContent();
	pWnd->m_FlowQuery.m_selAddress.ResetContent();

	for (int i = 0; i<NotifyInfo.Devices.size(); i++)
	{
		pWnd->m_Invite.m_selAddress.InsertString(i, NotifyInfo.Devices[i].Name);
		pWnd->m_PTZ.m_selAddress.InsertString(i, NotifyInfo.Devices[i].Name);
		pWnd->m_VideoQuery.m_selAddress.InsertString(i, NotifyInfo.Devices[i].Name);
		pWnd->m_Alarm.m_selAddress.InsertString(i, NotifyInfo.Devices[i].Name);
		pWnd->m_DeviceInfQuery.m_selAddress.InsertString(i, NotifyInfo.Devices[i].Name);
		pWnd->m_FlowQuery.m_selAddress.InsertString(i, NotifyInfo.Devices[i].Name);
	}
	*/
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
	//<��--���Ͱɱ������������ӵ�ģ�������Ϣ-->
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
	strTemp += "<Manufacturer>��������</Manufacturer>\r\n";
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
	strTemp += "<Manufacturer>��������</Manufacturer>\r\n";
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
	//<��--���Ͱɱ������������ӵ�ģ�������Ϣ-->
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
	strTemp += "<Manufacturer>��������</Manufacturer>\r\n";
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
	strTemp += "<Manufacturer>��������</Manufacturer>\r\n";
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
	//Զ��������Ϣ
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//����������Ϣ
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
	/*
 	char branch[20] = "z9hG4bK";
	for (int i = 0; i < 8; i++)
	{
		RandData = rand() % 10;
		branch[i+7] = RandData + '0';
	}
	osip_via_set_branch(SipNode->m_SipMsg.via, branch);//�����
	*/
	osip_via_set_host(SipNode->m_SipMsg.via,srcIP);

	//osip_call_id_set_host(SipNode->m_SipMsg.callid, srcIP);
	osip_call_id_set_number(SipNode->m_SipMsg.callid,CallID);//�����
	//������ע�����Ϣ��CallID��Ϣ
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	strcpy(pWnd->NodeTypeCallID.Host,srcIP);
	strcpy(pWnd->NodeTypeCallID.Num,CallID);

	//osip_from_set_displayname(SipNode->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipNode->m_SipMsg.from,FromTag);//�����
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

void CSipMsgProcess::SipInvite400(char **dst,osip_message_t *srcmsg)
{
	//����400 ����
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	osip_message_set_version(Sip200->m_SipMsg.msg,"SIP/2.0");
	osip_message_set_status_code(Sip200->m_SipMsg.msg,400);
	osip_message_set_reason_phrase(Sip200->m_SipMsg.msg,"");
	//osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);	
	//if ( strcmp(srcmsg->call_id->host,"")==0 )
	//{	
		osip_call_id_set_number(Sip200->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip200->m_SipMsg.callid,&dest);
		osip_message_set_call_id(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);
	//}
	//else
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
	//����200 OK����
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	osip_message_set_version(Sip200->m_SipMsg.msg,"SIP/2.0");
	osip_message_set_status_code(Sip200->m_SipMsg.msg,200);
	osip_message_set_reason_phrase(Sip200->m_SipMsg.msg,"OK");
	//osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);	
	//if ( strcmp(srcmsg->call_id->host,"") == 0)
	//{	
		osip_call_id_set_number(Sip200->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip200->m_SipMsg.callid,&dest);
		osip_message_set_call_id(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);
	//}
	//else
	osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	osip_from_clone(srcmsg->from,&Sip200->m_SipMsg.msg->from);	
	osip_to_clone(srcmsg->to,&Sip200->m_SipMsg.msg->to);	
	if (srcmsg->to->gen_params.nb_elt==0 )
	{
		osip_to_set_tag(Sip200->m_SipMsg.msg->to,FromTag);
	}	
	osip_cseq_clone(srcmsg->cseq,&Sip200->m_SipMsg.msg->cseq);
	//copy contact
	if (m_SipMsg.contact->gen_params.nb_elt > 0)
	{
		osip_message_get_contact(srcmsg, 0, &Sip200->m_SipMsg.contact);
		osip_contact_to_str(Sip200->m_SipMsg.contact, &dest);
		osip_message_set_contact(Sip200->m_SipMsg.msg, dest);
		//HWND   hnd=::FindWindow(NULL, _T("UAC"));	
		//CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
		//osip_message_set_contact(Sip200->m_SipMsg.msg,pWnd->contact);
		osip_free(dest);
	}
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
	//����100 try����
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip=new CSipMsgProcess;
	osip_message_set_version(Sip->m_SipMsg.msg,"SIP/2.0");
	osip_message_set_status_code(Sip->m_SipMsg.msg,100);
	osip_message_set_reason_phrase(Sip->m_SipMsg.msg,"");
	//osip_call_id_clone(srcmsg->call_id,&Sip->m_SipMsg.msg->call_id);
	//if ( strcmp(srcmsg->call_id->host,"")==0 )
	//{	
		osip_call_id_set_number(Sip->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip->m_SipMsg.callid,&dest);
		osip_message_set_call_id(Sip->m_SipMsg.msg,dest);
		osip_free(dest);
	//}
	//else
		osip_call_id_clone(srcmsg->call_id,&Sip->m_SipMsg.msg->call_id);	
	osip_from_clone(srcmsg->from,&Sip->m_SipMsg.msg->from);
	osip_to_clone(srcmsg->to,&Sip->m_SipMsg.msg->to);	
	//osip_to_set_tag(Sip->m_SipMsg.msg->to,FromTag);	100try
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	strcpy(pWnd->invite100tag,FromTag);
	osip_cseq_clone(srcmsg->cseq,&Sip->m_SipMsg.msg->cseq);
	//copy contact
	osip_message_get_contact(srcmsg,0,&Sip->m_SipMsg.contact);
	osip_contact_to_str(Sip->m_SipMsg.contact,&dest);
	osip_message_set_contact(Sip->m_SipMsg.msg,dest);	
	//osip_message_set_contact(Sip->m_SipMsg.msg,pWnd->contact);
	osip_free(dest);
	//copy via
	osip_message_get_via(srcmsg,0,&Sip->m_SipMsg.via);//
	osip_via_to_str(Sip->m_SipMsg.via,&dest);
	osip_message_set_via(Sip->m_SipMsg.msg,dest);
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	int i=osip_message_get_via(srcmsg,1,&Sip200->m_SipMsg.via);
	CString st0;
	if (1 == i)
	{
		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(Sip->m_SipMsg.msg,dest);
		st0 = dest;
		st0="Via: " + st0 + "\r\n";
		osip_free(dest);
	}
	else
	{
		st0="";
	}
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
	//����400 ����
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	osip_message_set_version(Sip200->m_SipMsg.msg,"SIP/2.0");
	osip_message_set_status_code(Sip200->m_SipMsg.msg,400);	
	osip_message_set_reason_phrase(Sip200->m_SipMsg.msg,"");
	//osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	//if ( strcmp(srcmsg->call_id->host,"")==0 )
	//{	
		osip_call_id_set_number(Sip200->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip200->m_SipMsg.callid,&dest);
		osip_message_set_call_id(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);
	//}
	//else
		osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	osip_from_clone(srcmsg->from,&Sip200->m_SipMsg.msg->from);
	osip_to_clone(srcmsg->to,&Sip200->m_SipMsg.msg->to);
	if (srcmsg->to->gen_params.nb_elt==0 )
	{
		osip_to_set_tag(Sip200->m_SipMsg.msg->to,FromTag);
	}
	osip_cseq_clone(srcmsg->cseq,&Sip200->m_SipMsg.msg->cseq);
	//copy contact
	osip_message_get_contact(srcmsg,0,&Sip200->m_SipMsg.contact);
	osip_contact_to_str(Sip200->m_SipMsg.contact,&dest);
	osip_message_set_contact(Sip200->m_SipMsg.msg,dest);
	//HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	//CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	//osip_message_set_contact(Sip200->m_SipMsg.msg,pWnd->contact);
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
		osip_free(dest);	
	}
	else
	{
		st0="";
	}
	osip_message_to_str(Sip200->m_SipMsg.msg,&dest,&len);
	memset(*dst,0,MAXBUFSIZE);
	memcpy(*dst,dest,len);
	osip_free(dest);
}

void CSipMsgProcess::DOKeepAliveMsg(char **dst,InfoServer m_InfoServer,InfoClient m_InfoClient,char *Xml)
{
	char FromTag[10];
	char CallID[10];
	//Զ��������Ϣ
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//����������Ϣ
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
	//osip_via_set_branch(via,"123456789");//�����
	// 	RandData=rand();	
	// 	char sdtr[10];	
	// 	char branch[20];
	// 	itoa(RandData,sdtr,16);
	// 	strcpy(branch,"z9hG4bK--");
	// 	strcat(branch,sdtr);
	/*
	char branch[20] = "z9hG4bK";
	for (int i = 0; i < 8; i++)
	{
		RandData = rand() % 10;
		branch[i + 7] = RandData + '0';
	}

	osip_via_set_branch(SipHeader->m_SipMsg.via,branch);//�����
	*/
	osip_via_set_host(SipHeader->m_SipMsg.via,srcIP);

	//osip_call_id_set_host(SipHeader->m_SipMsg.callid, srcIP);
	osip_call_id_set_number(SipHeader->m_SipMsg.callid,CallID);//�����

	//osip_from_set_displayname(SipHeader->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipHeader->m_SipMsg.from,FromTag);//�����
	osip_from_set_url(SipHeader->m_SipMsg.from,SipHeader->m_SipMsg.uriClient);
	//������ע�����Ϣ��CallID��Ϣ		
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
	//if ( strcmp(srcmsg->call_id->host,"")==0 )
	//{	
		osip_call_id_set_number(Sip200->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip200->m_SipMsg.callid,&dest);
		osip_message_set_call_id(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);
	//}
	//else
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
	if (1 == i)
	{

		osip_via_to_str(Sip200->m_SipMsg.via,&dest);
		osip_message_set_via(Sip200->m_SipMsg.msg,dest);
		st0=dest;
		st0="Via: "+st0+"\r\n";		
	}
	else
		st0="";
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
	//if ( strcmp(srcmsg->call_id->host,"")==0 )
	//{	
		osip_call_id_set_number(Sip200->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(Sip200->m_SipMsg.callid,&dest);
		osip_message_set_call_id(Sip200->m_SipMsg.msg,dest);
		osip_free(dest);
	//}
	//else
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

//��SIPͷ��XML�ĵ���Ϣ���������Ϣ
void CSipMsgProcess::Sip200Xml(char **dstBuf,osip_message_t *srcmsg,CString Xml)
{	
	char ToTag[10];
	int RandData;
	RandData=rand();	
	char str[8];		
	itoa(RandData,str,10);
	strcpy(ToTag,str);
	char *dest=NULL;
	size_t len;
	CSipMsgProcess *Sip200=new CSipMsgProcess;
	osip_message_set_version(Sip200->m_SipMsg.msg,"SIP/2.0");
	osip_message_set_status_code(Sip200->m_SipMsg.msg,200);
	osip_message_set_reason_phrase(Sip200->m_SipMsg.msg,"OK");
	//osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	osip_call_id_set_number(Sip200->m_SipMsg.callid,srcmsg->call_id->number);
	osip_call_id_to_str(Sip200->m_SipMsg.callid,&dest);
	osip_message_set_call_id(Sip200->m_SipMsg.msg,dest);
	osip_free(dest);

	osip_call_id_clone(srcmsg->call_id,&Sip200->m_SipMsg.msg->call_id);
	osip_from_clone(srcmsg->from,&Sip200->m_SipMsg.msg->from);
	osip_to_clone(srcmsg->to,&Sip200->m_SipMsg.msg->to);
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	/**modified by Bsp lee*/
	char *str2;
	osip_from_to_str(srcmsg->from, &str2);
	osip_message_set_from(Sip200->m_SipMsg.msg, str2);
	string strFromTag = str2;
	int tagStart = strFromTag.find("tag=", 0);
	string fromTag = strFromTag.substr(tagStart + 4, strFromTag.length() - tagStart - 3);
	strcpy(pWnd->alarmFromTag, fromTag.c_str());
	if (srcmsg->to->gen_params.nb_elt==0 )
	{
		osip_to_set_tag(Sip200->m_SipMsg.msg->to, ToTag);
		if (pWnd->balarmsubscribe)
		{
			strcpy(pWnd->alarmToTag,ToTag);
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
		AfxMessageBox("sip200ȱ�٣�Content-Type");
	}
	strtemp.insert(index,st);
	strcpy(*dstBuf,strtemp.c_str());

	osip_free(dest);
}

BOOL CSipMsgProcess::XmlInviteCreate(char** strInviteXml,char *srcXml)
{
	string strTemp(srcXml);		
	CString Format;
	CString Video;
	CString Audio;
	CString MaxBitrate;
	CString TransmitMode;
	CString Protocol;
	CString Multicast;
	string::size_type VariableStart;	
	string::size_type VariableEnd;	

	if( (VariableStart=strTemp.find("<Format>",0)) ==string::npos)
	{
		AfxMessageBox("ʵʱ������ȱ��Format�ֶ�");
		return FALSE;	
	}
							
	if ( (VariableEnd=strTemp.find("</Format>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("ʵʱ������ȱ��Format�ֶ�");
		return FALSE;	
	}	
	Format = strTemp.substr(VariableStart+8,VariableEnd-VariableStart-8).c_str();
	if( (VariableStart=strTemp.find("<Video>",0)) ==string::npos)			
	{
		AfxMessageBox("ʵʱ������ȱ��Video�ֶ�");
		return FALSE;	
	}					
	if ( (VariableEnd=strTemp.find("</Video>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("ʵʱ������ȱ��Video�ֶ�");
		return FALSE;	
	}				
	Video=strTemp.substr(VariableStart+7,VariableEnd-VariableStart-7).c_str();
	//if ((VariableStart = strTemp.find("<Stream>", 0)) == string::npos)
	//{
	//	AfxMessageBox("ʵʱ������ȱ��Stream�ֶ�");
	//	return FALSE;
	//}
	//if ((VariableEnd = strTemp.find("</Stream>", VariableStart + 1)) == string::npos)
	//{
	//	AfxMessageBox("ʵʱ������ȱ��/Stream�ֶ�");
	//	return FALSE;
	//}
	if( (VariableStart=strTemp.find("<Audio>",0)) ==string::npos)			
	{
		AfxMessageBox("ʵʱ������ȱ��Audio�ֶ�");
		return FALSE;	
	}								
	if ( (VariableEnd=strTemp.find("</Audio>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("ʵʱ������ȱ��Audio�ֶ�");
		return FALSE;	
	}			
	Audio=strTemp.substr(VariableStart+7,VariableEnd-VariableStart-7).c_str();
	if( (VariableStart=strTemp.find("<MaxBitrate>",0)) ==string::npos)			
	{
		AfxMessageBox("ʵʱ������ȱ��MaxBitrate�ֶ�");
		return FALSE;	
	}							
	if ( (VariableEnd=strTemp.find("</MaxBitrate>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("ʵʱ������ȱ��MaxBitrate�ֶ�");
		return FALSE;	
	}			
	MaxBitrate=strTemp.substr(VariableStart+12,VariableEnd-VariableStart-12).c_str();
 	if( (VariableStart=strTemp.find("<Multicast>",0)) ==string::npos)			
 	{
 		AfxMessageBox("ʵʱ������ȱ��Multicast�ֶ�");
 		return FALSE;	
 	}							
 	if ( (VariableEnd=strTemp.find("</Multicast>",VariableStart+1)) ==string::npos)		
 	{
 		AfxMessageBox("ʵʱ������ȱ��Multicast�ֶ�");
 		return FALSE;	
 	}			
 	Multicast = strTemp.substr(VariableStart+11,VariableEnd-VariableStart-11).c_str();
	string XmlInvite;	
	XmlInvite="<?xml version=\"1.0\"?>\r\n";
	XmlInvite+="<Response>\r\n";
	XmlInvite+="<Variable>RealMedia</Variable>\r\n";
	XmlInvite+="<Result>0</Result>\r\n";
	XmlInvite += "<Format>" + Format + "</Format>\r\n"; //�еĳ��̲�֧��720���޸�CIF
	XmlInvite += "<Video>" + Video + "</Video>\r\n";
	//XmlInvite += "<Stream>RTP</Stream>\r\n";
	XmlInvite += "<Audio>" + Audio + "</Audio>\r\n";
	XmlInvite += "<Bitrate>300</Bitrate>\r\n";
	XmlInvite += "<Multicast>" + Multicast + "</Multicast>\r\n";
	XmlInvite+="<SendSocket>";//192.168.1.7 UDP 2300</Socket>\r\n";
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);	
	if (Multicast == "1")//�鲥
		XmlInvite += "239.0.0.1";
	else//����
		XmlInvite += pWnd->m_InfoClient.IP;
	XmlInvite += " UDP 2300</SendSocket>\r\n";
	XmlInvite+="<DecoderTag>manufacturer=H3C ver=V30</DecoderTag>\r\n";	
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
		AfxMessageBox("ʵʱ������ȱ��Privilege�ֶ�");
		return FALSE;	
	}								
	if ( (VariableEnd=strTemp.find("</Privilege>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("ʵʱ������ȱ��Privilege�ֶ�");
		return FALSE;	
	}	
	UserCode=strTemp.substr(VariableStart+11,VariableEnd-VariableStart-11);
	if( (VariableStart=strTemp.find("<Command>",0)) ==string::npos)			
	{
		AfxMessageBox("ʵʱ������ȱ��Command�ֶ�");
		return FALSE;	
	}
	if ( (VariableEnd=strTemp.find("</Command>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("ʵʱ������ȱ��Command�ֶ�");
		return FALSE;	
	}				
 	PTZCommand=strTemp.substr(VariableStart+10,VariableEnd-VariableStart-10);
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
	string Privilege;
	//HWND   hnd = ::FindWindow(NULL, _T("UAC"));
	//CUACDlg*  pWnd = (CUACDlg*)CWnd::FromHandle(hnd);
	string::size_type VariableStart;	
	string::size_type VariableEnd;
	if ((VariableStart = strTemp.find("<Privilege>", 0)) == string::npos)
	{
		AfxMessageBox("���������ã�ȱ��Privilege�ֶΣ�", MB_OK | MB_ICONERROR);
		return FALSE;						
	}
	if ((VariableEnd = strTemp.find("</Privilege>", VariableStart + 1)) == string::npos)
	{
		AfxMessageBox("���������ã�ȱ��/Privilege�ֶΣ�", MB_OK | MB_ICONERROR);
		return FALSE;
	}
	Privilege = strTemp.substr(VariableStart+11,VariableEnd-VariableStart-11);
	string XmlEncoderSet;
	XmlEncoderSet = "<?xml version=\"1.0\"?>\r\n";
	XmlEncoderSet += "<Response>\r\n";
	XmlEncoderSet += "<ControlResponse>\r\n";
	XmlEncoderSet += "<Variable>EncoderSet</Variable>\r\n";
	XmlEncoderSet += "<Result>0</Result>\r\n";
	XmlEncoderSet += "<Privilege>"+ Privilege + "</Privilege>\r\n";
	XmlEncoderSet += "</ControlResponse>\r\n";
	XmlEncoderSet += "</Response>\r\n";	
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
	//Զ��������Ϣ
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//����������Ϣ
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
// 	RandData=rand();	
// 	char sdtr[10];	
// 	char branch[20];
// 	itoa(RandData,sdtr,16);
// 	strcpy(branch,"z9hG4bK--");
// 	strcat(branch,sdtr);
	/*
	char branch[20] = "z9hG4bK";
	for (int i = 0; i < 8; i++)
	{
		RandData = rand() % 10;
		branch[i + 7] = RandData + '0';
	}
 	osip_via_set_branch(SipHeader->m_SipMsg.via,branch);//�����
	*/
	osip_via_set_host(SipHeader->m_SipMsg.via,srcIP);	
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);	
	//osip_call_id_clone(srcmsg->call_id,&SipHeader->m_SipMsg.msg->call_id);
	//osip_from_clone(srcmsg->from,&SipHeader->m_SipMsg.msg->to);	
	osip_from_set_displayname(SipHeader->m_SipMsg.from,srcUserName);
	osip_from_set_url(SipHeader->m_SipMsg.from,SipHeader->m_SipMsg.uriClient);
	if (srcmsg->to->gen_params.nb_elt==0 )
	{
		osip_from_set_tag(SipHeader->m_SipMsg.from, pWnd->alarmToTag);
		//osip_to_set_tag(SipHeader->m_SipMsg.msg->to, pWnd->alarmFromTag);
	}	
	osip_to_set_displayname(SipHeader->m_SipMsg.to,dstUserName);	
	osip_to_set_url(SipHeader->m_SipMsg.to,SipHeader->m_SipMsg.uriServer);		
	//osip_from_set_displayname(SipHeader->m_SipMsg.from,srcUserName);
	//osip_from_set_tag(SipHeader->m_SipMsg.from,FromTag);//�����
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
	//if ( strcmp(srcmsg->call_id->host,"")==0 )
	//{	
		osip_call_id_set_number(SipHeader->m_SipMsg.callid,srcmsg->call_id->number);
		osip_call_id_to_str(SipHeader->m_SipMsg.callid,&dest);
		osip_message_set_call_id(SipHeader->m_SipMsg.msg,dest);
		osip_free(dest);
	//}
	//else
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
		AfxMessageBox("������ȱVariable�ֶ�");
		return FALSE;
	}					
	if ( (VariableEnd=strTemp.find("</Variable>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("������ȱVariable�ֶ�");
		return FALSE;
	}	
	
	if( (VariableStart=strTemp.find("<Privilege>",0)) ==string::npos)			
	{
		AfxMessageBox("������ȱPrivilege�ֶ�");
		return FALSE;
	}							
	if ( (VariableEnd=strTemp.find("</Privilege>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("������ȱPrivilege�ֶ�");
		return FALSE;
	}	
	InfoAlarm infoAlarm;
	infoAlarm.UserCode = strTemp.substr(VariableStart+11,VariableEnd-VariableStart-11);
	
 	if( (VariableStart=strTemp.find("<Level>",0)) ==string::npos)			
 		return FALSE;	
 	if ( (VariableEnd=strTemp.find("</Level>",VariableStart+1)) ==string::npos)		
 		return FALSE;
 	infoAlarm.Level = strTemp.substr(VariableStart+7,VariableEnd-VariableStart-7);
	
	if( (VariableStart=strTemp.find("<AlarmType>",0)) ==string::npos)			
	{
		AfxMessageBox("������ȱAlarmType�ֶ�");
		return FALSE;
	}						
	if ( (VariableEnd=strTemp.find("</AlarmType>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("������ȱAlarmType�ֶ�");
		return FALSE;
	}
	infoAlarm.AlarmType=strTemp.substr(VariableStart+11,VariableEnd-VariableStart-11);
	
	if( (VariableStart=strTemp.find("<Address>",0)) ==string::npos)			
	{
		AfxMessageBox("������ȱAddress�ֶ�");
		return FALSE;
	}					
	
	if ( (VariableEnd=strTemp.find("</Address>",VariableStart+1)) ==string::npos)		
	{
		AfxMessageBox("������ȱAddress�ֶ�");
		return FALSE;
	}
	infoAlarm.Address = strTemp.substr(VariableStart+9,VariableEnd-VariableStart-9);
	
 	if( (VariableStart=strTemp.find("<AcceptIp>",0)) ==string::npos)			
 		return FALSE;						
 	if ( (VariableEnd=strTemp.find("</AcceptIp>",VariableStart+1)) ==string::npos)		
 		return FALSE;
 	infoAlarm.AcceptIP = strTemp.substr(VariableStart+10,VariableEnd-VariableStart-10);
 	
 	if( (VariableStart=strTemp.find("<AcceptPort>",0)) ==string::npos)			
 		return FALSE;						
 	if ( (VariableEnd=strTemp.find("</AcceptPort>",VariableStart+1)) ==string::npos)		
 		return FALSE;
 	infoAlarm.AcceptPort=strTemp.substr(VariableStart+12,VariableEnd-VariableStart-12);
	
	//���浽vector m_InfoAlarm��
	pWnd->m_InfoAlarm.push_back(infoAlarm);

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
	//Զ��������Ϣ
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//����������Ϣ
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
	//osip_via_set_branch(via,"123456789");//�����
// 	RandData=rand();	
// 	char sdtr[10];	
// 	char branch[20];
// 	itoa(RandData,sdtr,16);
// 	strcpy(branch,"z9hG4bK--");
// 	strcat(branch,sdtr);
// 	osip_via_set_branch(SipHeader->m_SipMsg.via,branch);//�����
	//osip_via_set_branch(SipHeader->m_SipMsg.via,"z9hG4bK--22bd9222");//�����
	osip_via_set_host(SipHeader->m_SipMsg.via,srcIP);

	//osip_call_id_set_host(SipHeader->m_SipMsg.callid, srcIP);
	osip_call_id_set_number(SipHeader->m_SipMsg.callid,CallID);//�����

	//osip_from_set_displayname(SipHeader->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipHeader->m_SipMsg.from,FromTag);//�����
	osip_from_set_url(SipHeader->m_SipMsg.from,SipHeader->m_SipMsg.uriClient);
	//������ע�����Ϣ��CallID��Ϣ		
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
	//Զ��������Ϣ
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//����������Ϣ
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
/*
	char branch[20] = "z9hG4bK";
	for (int i = 0; i < 8; i++)
	{
		RandData = rand() % 10;
		branch[i + 7] = RandData + '0';
	}
	osip_via_set_branch(SipHeader->m_SipMsg.via, branch);//�����
	*/
	osip_via_set_host(SipHeader->m_SipMsg.via,srcIP);
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	//osip_from_set_displayname(SipHeader->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipHeader->m_SipMsg.from,FromTag);//�����
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
	/**************************************************/
	/*modified by Bsp lee*/
	// there call id is alarm subscribe call id	
	int len = strlen(Common::nowNotifyEvent_ArarmCallID.c_str()) + 1;
	char * call_id = new char[len];
	strcpy(call_id, Common::nowNotifyEvent_ArarmCallID.c_str());
	osip_message_set_call_id(SipHeader->m_SipMsg.msg, call_id);
	osip_call_id_set_number(SipHeader->m_SipMsg.msg->call_id, call_id);
	/**************************************************/

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
	//Զ��������Ϣ
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//����������Ϣ
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
	//osip_via_set_branch(via,"123456789");//�����
	//osip_via_set_branch(SipHeader->m_SipMsg.via,"z9hG4bK--22cd7222");//�����
	// 	RandData=rand();	
	// 	char sdtr[8];	
	// 	char branch[20];
	// 	itoa(RandData,sdtr,16);	
	// 	strcpy(branch,"z9hG4bK-");
	// 	strcat(branch,sdtr);
	// 	osip_via_set_branch(SipHeader->m_SipMsg.via,branch);//�����
	osip_via_set_host(SipHeader->m_SipMsg.via,srcIP);
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	//osip_from_set_displayname(SipHeader->m_SipMsg.from,srcUserName);
	osip_from_set_tag(SipHeader->m_SipMsg.from,FromTag);//�����
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
	//Զ��������Ϣ
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//����������Ϣ
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
	//Զ��������Ϣ
	char *dstCode=(LPSTR)(LPCTSTR)m_InfoServer.UserAddress;
	char *dstUserName=(LPSTR)(LPCTSTR)m_InfoServer.UserName;
	char *dstIP=(LPSTR)(LPCTSTR)m_InfoServer.IP;
	char *dstPort=(LPSTR)(LPCTSTR)m_InfoServer.Port;
	//����������Ϣ
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
	switch (nto)
	{
	case 0://��֤InfoServer
		//strcmp(dstUserName,srcMsg->from->displayname)==0 &&
		//strcmp(srcUserName,srcMsg->to->displayname)==0 &&
		if (strcmp(dstCode, srcMsg->from->url->username) == 0 &&
			strcmp(dstIP, srcMsg->from->url->host) == 0 &&
			strcmp(dstPort, srcMsg->from->url->port) == 0 &&
			strcmp(srcCode, srcMsg->to->url->username) == 0 &&
			strcmp(srcIP, srcMsg->to->url->host) == 0 &&
			strcmp(srcPort, srcMsg->to->url->port) == 0)
		{
			return TRUE;
		}
		break;
	case 1://��֤InfoClient
		//strcmp(srcUserName,srcMsg->from->displayname)==0 &&
		//strcmp(dstUserName,srcMsg->to->displayname)==0 &&
		if (strcmp(srcCode, srcMsg->from->url->username) == 0 &&
			strcmp(srcIP, srcMsg->from->url->host) == 0 &&
			strcmp(srcPort, srcMsg->from->url->port) == 0 &&
			strcmp(srcCode, srcMsg->to->url->username) == 0 &&
			strcmp(srcIP, srcMsg->to->url->host) == 0 &&
			strcmp(srcPort, srcMsg->to->url->port) == 0)
		{
			return TRUE;
		}
		break;
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
	strTemp+="<RealPresetNum>49</RealPresetNum>\r\n";
    CString cst;
    cst.Format("%d", end-begin);
	strTemp += "<SendPresetNum>"+cst+"</SendPresetNum>\r\n";

	cst.Format("%d", 49-end);
	strTemp += "<RemainPresetNum>"+cst+"</RemainPresetNum>\r\n";
	//strTemp+="<FromIndex>"+cst+"</FromIndex>\r\n";
	//cst.Format("%d",end);
	//strTemp+="<ToIndex>"+cst+"</ToIndex>\r\n";
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
	strTemp+="<RealFileNum>2</RealFileNum>\r\n";
	CString cst;
	
	/*cst.Format("%d",begin);
	strTemp+="<FromIndex>"+cst+"</FromIndex>\r\n";
	cst.Format("%d",end);
	strTemp+="<ToIndex>"+cst+"</ToIndex>\r\n";
	//strTemp+="<DecoderTag>Manufacturer=H3C ver=V30</DecoderTag>\r\n";
	*/
	cst.Format("%d",end- begin);
	//strTemp += "<SendFileNum>" + cst + "</SendFileNum>\r\n";
	strTemp += "<SendFileNum>2</SendFileNum>\r\n";
	strTemp+="<FileInfoList>\r\n";

	//for (int i=begin*6;i<end*6;i++)
	//{
	//	strTemp+=HistoryVideoList[i]+"\r\n";
	//}
 	strTemp+="<Item>\r\n";
 	strTemp+="<Name>xiaoshan_20051101001.mp4</Name>\r\n";
 	strTemp+="<CreationTime>2017-06-06T01:00:00Z</CreationTime>\r\n";
 	strTemp+="<LastWriteTime>2017-06-076T12:00:00Z</LastWriteTime>\r\n";
 	strTemp+="<FileSize>500000</FileSize>\r\n";	
 	strTemp+="</Item>\r\n";

	strTemp += "<Item>\r\n";
	strTemp += "<Name>xiaoshan_20051101001.mp4</Name>\r\n";
	strTemp += "<CreationTime>2017-06-07T03:20:00Z</CreationTime>\r\n";
	strTemp += "<LastWriteTime>2017-06-07T12:30:00Z</LastWriteTime>\r\n";
	strTemp += "<FileSize>500000</FileSize>\r\n";
	strTemp += "</Item>\r\n";
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

int CSipMsgProcess::CreateXMLVideoQuery_h(char ** dstXML, CTime begin, CTime end, int max)
{
	CString strTemp;
	strTemp = "<?xml version=\"1.0\"?>\r\n";
	strTemp += "<Response>\r\n";
	strTemp += "<QueryResponse>\r\n";
	strTemp += "<Variable>FileList</Variable>\r\n";
	strTemp += "<Result>0</Result>\r\n";
	strTemp += "<RealFileNum>1</RealFileNum>\r\n";
	CString cst;

	/*cst.Format("%d",begin);
	strTemp+="<FromIndex>"+cst+"</FromIndex>\r\n";
	cst.Format("%d",end);
	strTemp+="<ToIndex>"+cst+"</ToIndex>\r\n";
	//strTemp+="<DecoderTag>Manufacturer=H3C ver=V30</DecoderTag>\r\n";
	*/
	cst.Format("%d", end - begin);
	strTemp += "<SendFileNum>" + cst + "</SendFileNum>\r\n";
	strTemp += "<FileInfoList>\r\n";

	//for (int i = (begin - 1) * 6; i<end * 6; i++)
	//{
	//	strTemp += HistoryVideoList[i] + "\r\n";
	//}
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

	strTemp += "</FileInfoList>\r\n";
	strTemp += "</QueryResponse>\r\n";
	strTemp += "</Response>\r\n";
	char *dst = (LPSTR)(LPCTSTR)strTemp;
	strcpy(*dstXML, dst);
	return 0;

}

int CSipMsgProcess::CreateXMLCatalogQuery(char **dstXML)
{
	HWND   hnd=::FindWindow(NULL, _T("UAC"));	
	CUACDlg*  pWnd= (CUACDlg*)CWnd::FromHandle(hnd);
	CString strTemp;
	strTemp = "<?xml version=\"1.0\"?>\r\n";
	strTemp += "<Response>\r\n";
	strTemp += "<QueryResponse>\r\n";
	strTemp += "<Variable>ItemList</Variable>\r\n";
	strTemp += "<Parent>"+pWnd->m_InfoClient.UserAddress+"</Parent>\r\n";	
	strTemp += "<TotalSubNum>30</TotalSubNum>\r\n";
	strTemp += "<TotalOnlineSubNum>3</TotalOnlineSubNum>\r\n";
	strTemp += "<FromIndex>1</FromIndex>\r\n";
	strTemp += "<ToIndex>3</ToIndex>\r\n";
	strTemp += "<SubNum>3</SubNum>\r\n";
	strTemp += "<SubList>\r\n";
	
	//CATLOG 1
	strTemp += "<Item>\r\n";
	strTemp += "<Name>CATLOG 01</Name>\r\n";
	strTemp += "<Address>252000001201001001</Address>\r\n";
	strTemp += "<ResType>0</ResType>\r\n";
	strTemp += "<ResSubType>0</ResSubType>\r\n";
	strTemp += "<Privilege>%00%01</Privilege>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>54</Longitude>\r\n";
	strTemp += "<Latitude>453</Latitude>\r\n";
	strTemp += "<Elevation>35</Elevation>\r\n";
	strTemp += "<Roadway>42</Roadway>\r\n";
	strTemp += "<PileNo>52</PileNo>\r\n";
	strTemp += "<AreaNo>1</AreaNo>\r\n";
	strTemp += "<UpdateTime>20170222T130000Z</UpdateTime>\r\n";
	strTemp += "</Item>\r\n";

	//CATLOG 2
	strTemp += "<Item>\r\n";
	strTemp += "<Name>CATLOG 02</Name>\r\n";
	strTemp += "<Address>252000001301001001</Address>\r\n";
	strTemp += "<ResType>0</ResType>\r\n";
	strTemp += "<ResSubType>0</ResSubType>\r\n";
	strTemp += "<Privilege>%00%01</Privilege>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>52</Longitude>\r\n";
	strTemp += "<Latitude>423</Latitude>\r\n";
	strTemp += "<Elevation>25</Elevation>\r\n";
	strTemp += "<Roadway>52</Roadway>\r\n";
	strTemp += "<PileNo>32</PileNo>\r\n";
	strTemp += "<AreaNo>1</AreaNo>\r\n";
	strTemp += "<UpdateTime>20170222T130000Z</UpdateTime>\r\n";
	strTemp += "</Item>\r\n";

	//IPC 01
	strTemp += "<Item>\r\n";
	strTemp += "<Name>IPC 01</Name>\r\n";
	strTemp += "<Address>252000001102001001</Address>\r\n";
	strTemp += "<ResType>1</ResType>\r\n";
	strTemp += "<Privilege>%11%02</Privilege>\r\n";
	strTemp += "<SeriesNumber>000000000213</SeriesNumber>\r\n";
	strTemp += "<Status>0</Status>\r\n";
	strTemp += "<Longitude>20</Longitude>\r\n";
	strTemp += "<Latitude>20</Latitude>\r\n";
	strTemp += "<Roadway>20</Roadway>\r\n";
	strTemp += "<Elevation>20</Elevation>\r\n";
	strTemp += "<PileNo>20</PileNo>\r\n";
	strTemp += "<Manufacturer>��������</Manufacturer>\r\n";
	strTemp += "<Model>20</Model>\r\n";
	strTemp += "<Chip>20</Chip>\r\n";
	strTemp += "<OperateType>ADD</OperateType>\r\n";
	strTemp += "</Item>\r\n";

	strTemp += "</SubList>\r\n";
	strTemp += "</QueryResponse>\r\n";
	strTemp += "</Response>\r\n";
	char *dst=(LPSTR)(LPCTSTR)strTemp;	
	strcpy(*dstXML,dst);
	return 0;
}

int CSipMsgProcess::CreateXMLCatalogQueryNote(char **dstXML)
{
	CString strTemp;
	strTemp = "<?xml version=\"1.0\"?>\r\n";
	strTemp += "<Response>\r\n";
	strTemp += "<QueryResponse>\r\n";
	strTemp += "<Variable>ItemList</Variable>\r\n";
	strTemp += "<Parent>0</Parent>\r\n";	
	strTemp += "<TotalSubNum>45</TotalSubNum>\r\n";
	strTemp += "<TotalOnlineSubNum>2</TotalOnlineSubNum>\r\n";
	strTemp += "<FromIndex>1</FromIndex>\r\n";
	strTemp += "<ToIndex>2</ToIndex>\r\n";
	strTemp += "<SubNum>2</SubNum>\r\n";
	strTemp += "<SubList>\r\n";

	strTemp += "<Item>\r\n";
	strTemp += "<Name>IPC 01</Name>\r\n";
	strTemp += "<Address>252000001111002001</Address>\r\n";
	strTemp += "<ResType>1</ResType>\r\n";
	strTemp += "<ResSubType>1</ResSubType>\r\n";
	strTemp += "<Privilege>321345</Privilege>\r\n";
	strTemp += "<Status>1</Status>\r\n";
	strTemp += "<Longitude>23</Longitude>\r\n";
	strTemp += "<Latitude></Latitude>\r\n";
	strTemp += "<Elevation>532</Elevation>\r\n";
	strTemp += "<Roadway>523</Roadway>\r\n";
	strTemp += "<PileNo>245</PileNo>\r\n";
	strTemp += "<AreaNo>531</AreaNo>\r\n";
	strTemp += "<UpdateTime>20170222T130000Z</UpdateTime>\r\n";
	strTemp += "</Item>\r\n";

	strTemp += "<Item>\r\n";
	strTemp += "<Name>IPC 02</Name>\r\n";
	strTemp += "<Address>252000001112002001</Address>\r\n";
	strTemp += "<ResType>4</ResType>\r\n";
	strTemp += "<ResSubType>5</ResSubType>\r\n";
	strTemp += "<Privilege>34565</Privilege>\r\n";
	strTemp += "<Status>5</Status>\r\n";
	strTemp += "<Longitude>54</Longitude>\r\n";
	strTemp += "<Latitude>453</Latitude>\r\n";
	strTemp += "<Elevation>35</Elevation>\r\n";
	strTemp += "<Roadway>42</Roadway>\r\n";
	strTemp += "<PileNo>52</PileNo>\r\n";
	strTemp += "<AreaNo>25</AreaNo>\r\n";
	strTemp += "<UpdateTime>20170222T130000Z</UpdateTime>\r\n";
	strTemp += "</Item>\r\n";

	strTemp += "</SubList>\r\n";
	strTemp += "</QueryResponse>\r\n";
	strTemp += "</Response>\r\n";

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
	strTemp = "<?xml version=\"1.0\"?>\r\n";
	strTemp += "<Response>\r\n";
	strTemp += "<QueryResponse>\r\n";
	strTemp += "<Variable>BandWidth</Variable>\r\n";
	strTemp += "<Result>0</Result>\r\n";	
	strTemp += "<Manufacturer>uniview</Manufacturer>\r\n";
	strTemp += "<All>256</All>\r\n";
	strTemp += "<Free>240</Free>\r\n";
	strTemp += "<MediaLink>16</MediaLink>\r\n";
	strTemp += "</QueryResponse>\r\n";
	strTemp += "</Response>\r\n";

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

BOOL CSipMsgProcess::NodeAnylse(InfoNotify& NotifyInfo, char *buf)
{
	string strTemp(buf);
	string temp;
	string::size_type VideoStart = 0;
	string::size_type VariableStart;
	string::size_type VariableEnd;
	//InfoVideo Video;
	int varCount = 0;
	int nVideo = 0;
	VariableStart = strTemp.find("<Parent>", VideoStart + 1);
	VariableEnd = strTemp.find("</Parent>", VariableStart + 1);
	if (VariableStart != string::npos && VariableEnd != string::npos)
		NotifyInfo.Parent = strTemp.substr(VariableStart + 8, VariableEnd - VariableStart - 8).c_str();
	/*
	VariableStart = strTemp.find("<TotalSubNum>", VideoStart + 1);
	VariableEnd = strTemp.find("</TotalSubNum>", VariableStart + 1);
	if (VariableStart != string::npos && VariableEnd != string::npos)
	NotifyInfo.TotalSubNum = strTemp.substr(VariableStart + 13, VariableEnd - VariableStart - 13).c_str();

	VariableStart = strTemp.find("<TotalOnlineSubNum>", VideoStart + 1);
	VariableEnd = strTemp.find("</TotalOnlineSubNum>", VariableStart + 1);
	if (VariableStart != string::npos && VariableEnd != string::npos)
	NotifyInfo.TotalOnlineSubNum = strTemp.substr(VariableStart + 8, VariableEnd - VariableStart - 8).c_str();

	VariableStart = strTemp.find("<Parent>", VideoStart + 1);
	VariableEnd = strTemp.find("</Parent>", VariableStart + 1);
	if (VariableStart != string::npos && VariableEnd != string::npos)
	NotifyInfo.Parent = strTemp.substr(VariableStart + 8, VariableEnd - VariableStart - 8).c_str();

	*/
	while ((VideoStart = strTemp.find("<Item>", VideoStart)) != string::npos)
	{
		InfoDvice infoDviceT;
		//Name�ֶ�
		if ((VariableStart = strTemp.find("<Name>", VideoStart + 1)) == string::npos)
			break;
		if ((VariableEnd = strTemp.find("</Name>", VariableStart + 1)) == string::npos)
			break;
		infoDviceT.Name = strTemp.substr(VariableStart + 6, VariableEnd - VariableStart - 6).c_str();

		//Address�ֶ�
		if ((VariableStart = strTemp.find("<Address>", VideoStart + 1)) == string::npos)
			break;
		if ((VariableEnd = strTemp.find("</Address>", VariableStart + 1)) == string::npos)
			break;
		infoDviceT.Address = strTemp.substr(VariableStart + 9, VariableEnd - VariableStart - 9).c_str();
		/*
		//ResType
		if ((VariableStart = strTemp.find("<ResType>", VideoStart + 1)) == string::npos)
		break;
		if ((VariableEnd = strTemp.find("</ResType>", VariableStart + 1)) == string::npos)
		break;
		infoDviceT.ResType = strTemp.substr(VariableStart + 9, VariableEnd - VariableStart - 9).c_str();
		*/
		NotifyInfo.Devices.push_back(infoDviceT);
		VideoStart = VariableEnd + 1;
	}
	return TRUE;
}

/**
�����������ò�����ʾ��UAC��
**/
void CSipMsgProcess::ShowEncoderParam(char * buffer)
{
	CString Format;
	CString FrameRate;
	CString BitRate;
	CString Priority;
	CString GOP;
	CString ImageQuality;
	string str = buffer;

	int fmtStart = str.find("<Format>", 0);
	int fmtEnd = str.find("</Format>", 0);
	Format = str.substr(fmtStart + 8, fmtEnd - fmtStart - 8).c_str();	

	int fmrStart = str.find("<FrameRate>", 0);
	int fmrEnd = str.find("</FrameRate>", 0);
	FrameRate = str.substr(fmrStart + 11, fmrEnd - fmrStart - 11).c_str();

	int brStart = str.find("<BitRate>", 0);
	int brEnd = str.find("</BitRate>", 0);
	BitRate = str.substr(brStart + 9, brEnd - brStart - 9).c_str();

	int gopStart = str.find("<GOP>", 0);
	int gopEnd = str.find("</GOP>", 0);
	GOP = str.substr(gopStart + 5, gopEnd - gopStart - 5).c_str();

	int pryStart = str.find("<Priority>", 0);
	int pryEnd = str.find("</Priority>", 0);
	Priority = str.substr(pryStart + 10, pryEnd - pryStart - 10).c_str();

	int imgqlyStart = str.find("<ImageQuality>", 0);
	int imgqlyEnd = str.find("</ImageQuality>", 0);
	ImageQuality = str.substr(imgqlyStart + 14, imgqlyEnd - imgqlyStart - 14).c_str();

	CString EncoderParam;

	EncoderParam += "Format: " + Format + "\r\n";
	EncoderParam += "FrameRate: " + FrameRate + "\r\n";
	EncoderParam += "BitRate: " + BitRate + "\r\n";
	EncoderParam += "GOP: " + GOP + "\r\n";
	EncoderParam += "Priority: " + Priority + "\r\n";
	EncoderParam += "ImageQuality: " + ImageQuality + "\r\n";

	HWND   hnd = ::FindWindow(NULL, _T("UAC"));
	CUACDlg*  pWnd = (CUACDlg*)CWnd::FromHandle(hnd);
	pWnd->m_CoderSet.m_EncoderParam.SetWindowTextA(EncoderParam);
	pWnd->m_CoderSet.GetDlgItem(IDC_EDIT_ENCODERPARAM)->SendMessage(WM_VSCROLL, SB_BOTTOM, 0);
}