#pragma once

#include <iostream>
#include "libPipe.h"
#include <detours.h>
using namespace std;

#define MAKE_HIDE(orig_addr, new_addr)\
{\
	LOGMSG("[!] :: orig addr "  + std::to_string((int64_t)orig_addr));\
	LOGMSG("[!] :: new addr "  + std::to_string((int64_t)new_addr));\
	DetourTransactionBegin();\
	DetourUpdateThread(GetCurrentThread());\
	DetourAttach(&(PVOID&)(orig_addr), new_addr);\
	er = DetourTransactionCommit();\
	if (er == NO_ERROR)\
	{\
		LOGMSG("[v] :: Detoured successfully " + func);\
	}\
	else\
	{\
		LOGMSG("[ERROR] :: detoured failed " + func + std::to_string(er));\
		return -1;\
	}\
}
