#include "stdafx.h"
#include "Common.h"


Common::Common()
{
}

const char * Common::EXPIRES_VALUE = "90";
const char * Common::MAX_FORWARD_VALUE = "70";
int Common::DEVICECATALOG_COUNT = 1;

char * Common::nowReservingEventMsg_ArarmCallID = NULL;//当前正在预定的报警事件CALLID
Common::~Common()
{
}
