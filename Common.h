#pragma once
#include <string>
using namespace std;
class Common
{
public:
	Common();
	~Common();

	static const char * EXPIRES_VALUE;
	static const char * MAX_FORWARD_VALUE;
	static int DEVICECATALOG_COUNT;
	static string nowNotifyEvent_ArarmCallID;//正在想通知的报警事件的CALLID

	static BOOL FLAG_Notify_EventReserve;//事件预定标志
};

