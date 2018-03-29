#pragma once
#include "DXP.h"
#include <string.h>
#include <osipparser2/headers/osip_via.h>
#include <osipparser2/headers/osip_call_id.h>
#include <osipparser2/osip_message.h>
#include <osipparser2/osip_parser.h>
#include <osipparser2/osip_uri.h>
#include <osipparser2/osip_port.h>
#include <osipparser2/osip_list.h>
#include <osipparser2/osip_headers.h>
#include <osipparser2/osip_const.h>
#include "UAC.h"
#include "UACDlg.h"

class CSipMsgProcess
{
public:
	CSipMsgProcess(void);
	~CSipMsgProcess(void);

private:
	struct SipMsg 
	{
		osip_message_t *msg;
		osip_via_t *via;
		osip_from_t *from;
		osip_to_t *to;
		osip_cseq_t *cseq;
		osip_contact_t *contact;
		osip_call_id_t *callid;
		osip_content_type *content_type;
		osip_content_length *content_length;
		osip_uri_t *uriServer;
		osip_uri_t *uriClient;
	} m_SipMsg;
	
	//event CmdType
	int m_Type;
public:
	int SipParser(char *buffer,int Msglength);
	BOOL SipVerify(InfoServer m_InfoServer,InfoClient m_InfoClient,osip_message_t *srcMsg,int nto);
	BOOL RegisterSipVerify(InfoServer m_InfoServer,InfoClient m_InfoClient,osip_message_t *srcMsg,int nto);
	void DOKeepAliveMsg(char **dst,InfoServer m_InfoServer,InfoClient m_InfoClient,char *Xml);
	//register message
	int SipRegisterOrQuitCreate(bool isRegister,char **strRegister,InfoServer m_InfoServer,InfoClient m_InfoClient);
	int SipRegisterOrQuitWithAuthCreate(char **strRegister,InfoServer m_InfoServer,InfoClient m_InfoClient,osip_message_t *srcmsg);
	//node message
	void XmlNodeCreate(char** strNodeXml);
	void XmlNodeCreate1(char** strNodeXml); 
	void XmlNodeCreate2(char** strNodeXml);
	void SipNodeXmlMsg(char **strNode,InfoServer m_InfoServer,InfoClient m_InfoClient,char *NodeXml,osip_message_t *srcmsg);
	//response XML message
	BOOL XmlInviteCreate(char** strInviteXml,char *srcXml);
	BOOL XmlPTZCreate(char** strPTZXml,char *srcXml);
	BOOL XmlEncoderSetCreate(char** strEncoderSetXml,char *srcXml);
	//alarm subscribe notify
	void SipAlarmSubscribeNotify(char **dst,InfoServer m_InfoServer,InfoClient m_InfoClient,osip_message_t *srcmsg);
	BOOL XmlAlarmCreate(char** strAlarmXml,char *srcXml);


	//clone from and to CmdType
	void Sip200OK(char **dst,osip_message_t *srcmsg);
	void SipInvite400(char **dst,osip_message_t *srcmsg);
	void SipInvite200Xml(char **dstBuf,osip_message_t *srcmsg,CString Xml);
	void SipCancel200Xml(char **dstBuf,osip_message_t *srcmsg);
	void Sip100Try(char **dst,osip_message_t *srcmsg);
	void Sip400(char **dst,osip_message_t *srcmsg);
	void Sip200Xml(char **dstBuf,osip_message_t *srcmsg,CString Xml);
	void SipXmlMsg(char **dst,InfoServer m_InfoServer,InfoClient m_InfoClient,char *Xml);

	//alarm notify send
	void SipAlarmNotifyXmlMsg(char **dst,InfoServer m_InfoServer,InfoClient m_InfoClient,char *Xml);
	void SipNotifyXmlMsg(char **dst,InfoServer m_InfoServer,InfoClient m_InfoClient,char *Xml);
	//create video query XML message
	int CreateXMLptzPreBitQuery_c(char **dstXML,int begin,int end);
	int CreateXMLVideoQuery(char **dstXML);
	int CreateXMLVideoQuery_c(char **dstXML,int begin,int end);
	int CreateXMLVideoQuery_h(char **dstXML, CTime begin, CTime end, int max);
	int CreateXMLCatalogQuery(char **dstXML);

	/****************************************************************************************************************************/
	/*add some function for GB28181**********/
	/****************************************************************************************************************************/
	void SipAlarmEventNoticeDistribute(char **dst, InfoServer m_InfoServer, InfoClient m_InfoClient, char *Xml);
	
	int CreateXMLVideoAudioQueryNode(char **dstXML);
	void SipVideoAudioQueryXml(char **dst, InfoServer m_InfoServer, InfoClient m_InfoClient, char *Xml, osip_uri_param_t *FromTag);

	int CreateXMLDeviceInfoQueryNode(char **dstXML);
	void SipDeviceInfoQueryXml(char **dst, InfoServer m_InfoServer, InfoClient m_InfoClient, char *Xml, osip_uri_param_t *FromTag);

	int CreateXMLCatalogQueryNote(char ** dstXML);
	void SipCatalogQueryXml(char **dst, InfoServer m_InfoServer, InfoClient m_InfoClient, char *Xml, osip_uri_param_t *FromTag);
	
	int CreateXMLDeviceStatusQueryNode(char ** dstXML);  
	void SipDeviceStatusQueryXml(char **dst, InfoServer m_InfoServer, InfoClient m_InfoClient, char *Xml, osip_uri_param_t *FromTag);
	

	int CreateXMLFlowQuery(char **dstXML);
	void SipBYE(char **dst,osip_message_t *srcmsg);

	BOOL NodeAnylse(InfoNotify & NotifyInfo, char * buf);

	void ShowEncoderParam(char * buffer);
};