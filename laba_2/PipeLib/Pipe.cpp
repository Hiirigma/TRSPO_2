#include "libPipe.h"

#pragma comment(lib, "advapi32.lib")

#include <AclAPI.h>
#include <tchar.h>

//C:\Users\hiirigma\Desktop\oop_2.txt
Pipe::Pipe(const char *name)
{
	this->hPipe = nullptr;
	this->pipename = name;
}

Pipe::~Pipe()
{
	CloseHandle(this->hPipe);
	this->hPipe = nullptr;
}

void Pipe::createNamedPipe()
{
	LOG("Pipe_log");
	int bufsize = 512;
	SECURITY_ATTRIBUTES sa;
	if (this->createSecurityAttributes(&sa) < 0)
	{
		std::string error("[ERROR] getSecurityDescriptor failed :: " + std::to_string(GetLastError()));
		throw error;
	}

	this->hPipe = CreateNamedPipe(
		this->pipename.c_str(),     // pipe name 
		PIPE_ACCESS_DUPLEX,         // read/write access 
		PIPE_TYPE_MESSAGE |         // message type pipe 
		PIPE_READMODE_MESSAGE |     // message-read mode 
		PIPE_WAIT |                 // blocking mode 
		PIPE_ACCEPT_REMOTE_CLIENTS,
		PIPE_UNLIMITED_INSTANCES,   // max. instances  
		bufsize,                    // output buffer size 
		bufsize,                    // input buffer size 
		0,                          // client time-out 
		&sa);                       // security attribute 

	if (INVALID_HANDLE_VALUE == this->hPipe)
	{
		std::string error("[ERROR] CreateNamedPipe failed :: " + std::to_string(GetLastError()));
		throw error;
	}
	LOGMSG("[!] Exit from createNamedPipe");
}


void Pipe::waitForClient()
{
	LOG("Pipe_log");
	BOOL f_connected = FALSE;

	while (true)
	{
		// Wait for the client to connect; if it succeeds, 
		// the function returns a nonzero value. If the function
		// returns zero, GetLastError returns ERROR_PIPE_CONNECTED
		f_connected = ConnectNamedPipe(this->hPipe, nullptr) ?
			TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (f_connected)
		{
			return;
		}

		Sleep(300);
	}
	LOGMSG("[!] Exit from waitForClient");
}

void Pipe::openNamedPipe()
{
	DWORD dwMode = PIPE_READMODE_MESSAGE;
	LOG("Pipe_log");
	// Try to open a named pipe; wait for it, if necessary
	while (true)
	{
		this->hPipe = CreateFile(
			this->pipename.c_str(), // pipe name 
			GENERIC_READ |          // read and write access 
			GENERIC_WRITE,
			0,                      // no sharing 
			nullptr,                   // default security attributes
			OPEN_EXISTING,          // opens existing pipe 
			0,                      // default attributes 
			nullptr);                  // no template file 

		// Break if the pipe handle is invalid
		if (INVALID_HANDLE_VALUE != this->hPipe)
		{
			break;
		}

		// Exit if an error other than ERROR_PIPE_BUSY occurs
		if (ERROR_PIPE_BUSY != GetLastError())
		{
			std::string error("[ERROR] :: CreateFileA failed :: " + std::to_string(GetLastError()));
			throw error;
		}

		// All pipe instances are busy, so wait for 2 seconds 
		if (!WaitNamedPipe(pipename.c_str(), 1000))
		{
			std::string error("[ERROR] :: WaitNamedPipeA failed :: " + std::to_string(GetLastError()));
			throw error;
		}

		Sleep(100);
	}

	// The pipe connected; change to message-read mode
	if (!SetNamedPipeHandleState(this->hPipe, &dwMode, nullptr, nullptr))
	{
		std::string error("[ERROR] :: SetNamedPipeHandleState failed :: " + std::to_string(GetLastError()));
		throw error;
	}
	LOGMSG("[!] Exit from openNamedPipe");
}



int Pipe::receiveMessage(std::string& message)
{
	char buffer[512] = {0};
	DWORD cbRead = 0;
	LOG("Pipe_log");
	BOOL fSuccess = ReadFile(
		this->hPipe, // pipe handle 
		buffer,      // buffer to receive reply 
		512,     // size of buffer 
		&cbRead,     // number of bytes read 
		nullptr);    // not overlapped 

	if (!fSuccess)
	{
		std::string error("[ERROR] ReadFile failed :: " + std::to_string(GetLastError()));
		throw error;
	}

	if (0 != cbRead)
	{
		message.append(buffer, cbRead);
	}
	LOGMSG("[!] Exit from receiveMessage");
	return cbRead;
}


void Pipe::sendMessage(const std::string& message)
{
	LOG("Pipe_log");
	DWORD cbWritten;
	BOOL fSuccess = WriteFile(
		this->hPipe,      // handle to pipe 
		message.c_str(),  // buffer to write from 
		message.length(), // number of bytes to write 
		&cbWritten,       // number of bytes written 
		nullptr);         // not overlapped I/O 

	if (!fSuccess || cbWritten != message.length())
	{
		std::string error("[ERROR] WriteFile failed :: " + std::to_string(GetLastError()));
		throw error;
	}
	LOGMSG("[!] Exit from sendMessage");
}

int Pipe::createSecurityAttributes(SECURITY_ATTRIBUTES* sa)
{
	LOG("Pipe_log");
	PSID pEveryoneSID = nullptr;
	PACL pACL = nullptr;
	PSECURITY_DESCRIPTOR pSD;
	EXPLICIT_ACCESS ea;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	LOGMSG("[!] Entered in createSecurityAttributes");
	// Create a well-known SID for the Everyone group
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
		SECURITY_WORLD_RID,
		0, 0, 0, 0, 0, 0, 0,
		&pEveryoneSID))
	{
		LOGMSG("[ERROR] AllocateAndInitializeSid failed :: " + std::to_string(GetLastError()));
		return -1;
	}

	// Initialize an EXPLICIT_ACCESS structure for an ACE.
	// The ACE will allow Everyone full control to object
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = GENERIC_ALL;
	ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = static_cast<LPTSTR>(pEveryoneSID);

	// Create a new ACL that contains the new ACEs.

	if (ERROR_SUCCESS != SetEntriesInAcl(1, &ea, nullptr, &pACL))
	{
		LOGMSG("[ERROR] SetEntriesInAcl failed :: " + std::to_string(GetLastError()));
		return -1;
	}

	// Initialize a security descriptor.
	pSD = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH));
	if (nullptr == pSD)
	{
		LOGMSG("[ERROR] LocalAlloc failed :: " + std::to_string(GetLastError()));
		return -1;
	}

	if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
	{
		LOGMSG("[ERROR] InitializeSecurityDescriptor failed :: " + std::to_string(GetLastError()));
		return -1;
	}

	// Add the ACL to the security descriptor.
	if (!SetSecurityDescriptorDacl(pSD, TRUE, pACL, FALSE))
	{
		LOGMSG("[ERROR] SetSecurityDescriptorDacl failed :: " + std::to_string(GetLastError()));
		return -1; 
	}

	// Initialize a security attributes structure.
	sa->nLength = sizeof(SECURITY_ATTRIBUTES);
	sa->lpSecurityDescriptor = pSD;
	sa->bInheritHandle = FALSE;
	LOGMSG("[!] Exit from createSecurityAttributes");
	return 0;
}