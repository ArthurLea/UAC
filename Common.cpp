#include "stdafx.h"
#include "Common.h"
Common::Common()
{
}

const char * Common::EXPIRES_VALUE = "60";
const char * Common::MAX_FORWARD_VALUE = "70";
int Common::DEVICECATALOG_COUNT = 1;

string Common::nowNotifyEvent_ArarmCallID = "";//��ǰ����Ԥ���ı����¼�CALLID

BOOL Common::FLAG_Notify_EventReserve = false;//���б����¼�Ԥ��ʱΪtrue
Common::~Common()
{
}
