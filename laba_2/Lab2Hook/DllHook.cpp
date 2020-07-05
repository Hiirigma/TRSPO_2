#include <iostream>
#include "libPipe.h"
#include <detours.h>
using namespace std;
extern int hideFile(const string&);

string global_function = {0};
Pipe* glob_pipe;
BOOLEAN flag = FALSE;

extern "C" LPVOID glob_pointer = nullptr;
extern "C" void AsmHook();
extern "C" VOID hookCallback()
{
	glob_pipe->sendMessage("CALLED " + global_function);
}

BOOL pipeHandler()
{
	int recv = 0;
	string task;
	Pipe *pipe = new Pipe(PIPE_NAME);
	LONG res = 0;
	string command;
	string func;
	string file;
	// Opening the existing pipe and receiving task from injector

	try
	{
		pipe->openNamedPipe();

		LOGMSG("[OK] :: Pipe has been opened");

		while (true)
		{
			recv = pipe->receiveMessage(task);
			if (0 != recv)
			{
				break;
			}

			LOGMSG("[!] :: Task hasn't been received. Waiting...");
			Sleep(50);
		}
	}
	catch (string error)
	{
		LOGMSG("[ERROR] Can't work with named pipe from dll :: " + error);
		return FALSE;
	}

	LOGMSG("[OK] :: Task from server has been received: ");

	command = task.substr(0, 5);
	
	if ("-func" == command)
	{
		func = task.substr(6, task.length());
		
		global_function = func;
		glob_pipe = pipe;
		
		if (FALSE == flag || nullptr == glob_pointer)
		{
			glob_pointer = static_cast<LPVOID>(GetProcAddress(GetModuleHandle("kernel32.dll"), func.c_str()));
			if (nullptr == glob_pointer)
			{
				LOGMSG("[ERROR] :: GetProcAddress :: " + to_string(GetLastError()));
				return TRUE;
			}
			flag = TRUE;
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&static_cast<PVOID&>(glob_pointer), AsmHook);
			res = DetourTransactionCommit();
			if (NO_ERROR == res)
			{
				LOGMSG("[v] :: Detoured successfully func :: " + func);
			}
			else
			{
				LOGMSG(" [ERROR] :: detoured failed :: " + to_string(res) + " func :: " + func);
				return TRUE;
			}
		}
		
	}
	else if ("-hide" == command)
	{
		file = task.substr(6, task.length());
		hideFile(file);
		delete pipe;
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}


//DllMain
BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpReserved)  // reserved
{

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		LOGMSG("[!] :: Process attach");
		DisableThreadLibraryCalls(hinstDLL);
		if (!pipeHandler())
		{
			return FALSE;
		}
		break;
		
	case DLL_PROCESS_DETACH:
		LOGMSG("[!] :: Process detach");
		break;
	}
	
	return TRUE;
	
}