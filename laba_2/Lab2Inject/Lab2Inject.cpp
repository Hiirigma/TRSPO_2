#include "Lab2Inject.h"

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	LOG("Injector_log");
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		nullptr,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		LOGMSG("[ERROR] :: LookupPrivilegeValue error :: " + to_string(GetLastError()));
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		nullptr,
		nullptr))
	{
		LOGMSG("[ERROR] :: AdjustTokenPrivileges error :: "+ to_string(GetLastError()));
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		LOGMSG("[ERROR] ::The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}


HANDLE getProcHandleByName(char* proc_name)
{
	LOG("Injector_log");
	HANDLE h_process = nullptr;
	HANDLE h_snapshot = nullptr;

	PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

	// Takes a snapshot of the all processes in the system
	h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == h_snapshot)
	{
		LOGMSG("[ERROR] :: CreateToolhelp32Snapshot failed :: " + to_string(GetLastError()));
		return nullptr;
	}

	// Retrieve information about the first process
	if (!Process32First(h_snapshot, &pe32))
	{
		LOGMSG("[ERROR] :: Process32First failed :: " + to_string(GetLastError()));
		CloseHandle(h_snapshot);
		return nullptr;
	}

	// Now walk the snapshot of processes
	do
	{
		if (std::string(pe32.szExeFile) == std::string(proc_name))
		{
			h_process = OpenProcess(
				PROCESS_CREATE_THREAD 
				| PROCESS_QUERY_INFORMATION 
				| PROCESS_VM_OPERATION 
				| PROCESS_VM_READ 
				| PROCESS_VM_WRITE, 
				FALSE, 
				pe32.th32ProcessID);
			if (nullptr == h_process)
			{
				LOGMSG("[ERROR] :: OpenProcess failed :: " + to_string(GetLastError()));
				CloseHandle(h_snapshot);
				return nullptr;
			}

			CloseHandle(h_snapshot);
			return h_process;
		}
	} while (Process32Next(h_snapshot, &pe32));

	CloseHandle(h_snapshot);
	return nullptr;
}

HANDLE getProcHandle(char* argum, char* procNameId)
{
	LOG("Injector_log");
	HANDLE hProcess = nullptr;
	HANDLE hToken = nullptr;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		LOGMSG("[ERROR] :: OpenProcessToken Error :: " + to_string(GetLastError()));
	}
	else {
		
		if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
			LOGMSG("[ERROR] :: Lab2_SetPrivilegeSE_DEBUG_NAME Error :: " + to_string(GetLastError()));
		}
	
	}

	if (0 == strcmp(argum, "-pid"))
	{
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, std::stoi(procNameId));
		if (!hProcess)
		{
			LOGMSG("[ERROR] :: OpenProcess failed :: " + to_string(GetLastError()));
		}

	}
	else if (0 == strcmp(argum, "-name"))
	{
		hProcess = getProcHandleByName(procNameId);
	}
	else
	{
		LOGMSG("[ERROR] :: Invalid argument specifier :: " + to_string(GetLastError()));
	}
	
	return hProcess;
}


HANDLE dllInjector(HANDLE hProcess, const std::string& dllPath)
{
	LOG("Injector_log");
	HANDLE h_thread = nullptr;
	LPVOID lpvResult = nullptr;
	LOGMSG("[v] ENTER :: dllInjector");

	lpvResult = VirtualAllocEx(hProcess, nullptr, dllPath.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!lpvResult) {
		LOGMSG("[ERROR] :: VirtualAllocEx failed :: " + to_string(GetLastError()));
		return nullptr;
	}

	if (!WriteProcessMemory(hProcess, lpvResult, dllPath.c_str(), dllPath.size(), nullptr))
	{
		LOGMSG("[ERROR] :: WriteProcessMemory failed :: " + to_string(GetLastError()));
		return nullptr;
	}

	h_thread = CreateRemoteThread(hProcess, nullptr, 0,
		(LPTHREAD_START_ROUTINE)LoadLibraryA, lpvResult, 0, nullptr);
	if (!h_thread)
	{
		LOGMSG("[ERROR] :: CreateRemoteThread failed :: " + to_string(GetLastError()));
		return nullptr;
	}

	return h_thread;
}


int main(int argc, char* argv[]) 
{
	LOG("Injector_log");
	if (argc < 4)
	{
		LOGMSG("[!] Usage :: app.exe -name proc.exe (–pid PID) -func FUNCTION_NAME (-hide FILE_PATH)\n");
		return -1;
	}
	
	HANDLE h_process = nullptr;
	int res = 0;
	char cur_dir[_MAX_PATH] = { 0 };
	char file_path[_MAX_PATH] = { 0 };
	string msg;
	string path;
	string fileName;
	Pipe pipe_serv(PIPE_NAME);
	string task;


	if (strcmp(argv[3], "-hide") == 0)
	{
		fileName = argv[4];
		if (fileName.find(':') == std::string::npos)
		{
			if (GetFullPathName(fileName.c_str(), _MAX_PATH, file_path, nullptr) == 0)
			{
				return -1;
			}
			fileName = file_path;
		}
		task = argv[3];
		task += " " + fileName;
	}
	else
	{
		task = argv[3];
		task += " ";
		task += argv[4];
	}
	
	GetCurrentDirectory(MAX_PATH, cur_dir);
	path.append(cur_dir);
	path.append(DLL_NAME);
	
	try
	{
		pipe_serv.createNamedPipe();
	}
	catch (std::string & error)
	{
		LOGMSG("[ERROR] :: Unable to create named pipe :: " + error);
		return -1;
	}

	LOGMSG("[v] OK :: Pipe has been created");
	
	h_process = getProcHandle(argv[1], argv[2]);

	if (h_process == NULL)
	{
		LOGMSG("[ERROR] :: Process handle has not been got");
		return -1;
	}

	LOGMSG("[v] OK :: Process handle has been got");

	if (nullptr == dllInjector(h_process, path))
	{
		LOGMSG("[ERROR] :: Unable to inject DLL to process!");
		return -1;
	}
	
	LOGMSG("[v] OK :: DLL "+ path + " has been injected to "+ argv[2]);
	
	LOGMSG("[v] Waiting for a pipe client... " );
	
	pipe_serv.waitForClient();

	LOGMSG("[v] OK :: Pipe client has been connected");

	try
	{
		LOGMSG("[!] Message to pipe :: " + task);
		pipe_serv.sendMessage(task);
	}
	catch (std::string & error)
	{
		LOGMSG("[ERROR] :: Unable to send message to pipe :: "+ error);
		return -1;
	}

	LOGMSG("[v] :: Task to client has been sent");

	if (0 == strcmp(argv[3], "-func"))
	{
		LOGMSG("[v] Waiting messages from client... ");

		while (true)
		{
			try
			{
				res = pipe_serv.receiveMessage(msg);
			}
			catch (string & error)
			{
				LOGMSG("[ERROR] :: Unable to receive message to pipe :: " + error);
				return -1;
			}

			if (res)
			{
				LOGMSG("[!!!] :: " + msg);
				msg.clear();
			}

			Sleep(100);
		}
	}
	LOGMSG("[v] :: Injector has finished");

	return 0;
}