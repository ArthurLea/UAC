#include "stdafx.h"
#include "Common.h"
Common::Common()
{
}

const char * Common::EXPIRES_VALUE = "60";
const char * Common::MAX_FORWARD_VALUE = "70";
int Common::DEVICECATALOG_COUNT = 1;

string Common::nowNotifyEvent_ArarmCallID = "";//当前正在预定的报警事件CALLID

BOOL Common::FLAG_Notify_EventReserve = false;//当有报警事件预定时为true
Common::~Common()
{
}
