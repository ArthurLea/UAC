#pragma once
class Common
{
public:
	Common();
	~Common();

	static const char * EXPIRES_VALUE;
	static const char * MAX_FORWARD_VALUE;
	static int DEVICECATALOG_COUNT;
	static char *nowReservingEventMsg_ArarmCallID;//正在想预定的报警事件

	//static vector<string> curAlreadyReserveEvent;//当前已经预定了的事件消息存储，用于判断是否重复预定
	//static string nowReservingEventMsg;//正在想预定的报警事件
};

