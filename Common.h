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
	static string nowNotifyEvent_ArarmCallID;//������֪ͨ�ı����¼���CALLID

	static BOOL FLAG_Notify_EventReserve;//�¼�Ԥ����־
};

