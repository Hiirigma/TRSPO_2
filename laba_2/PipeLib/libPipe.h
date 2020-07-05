#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#define PIPE_NAME "\\\\.\\pipe\\lab2namedpipe"

#ifdef _DEBUG
#define LOGMSG(str,...) do { std::cout << "[!] LOG MESSAGE :: " << str << std::endl; } while( false )
#else
#define LOGMSG(str) do { } while ( false )
#endif

#ifdef _DEBUG
#define LOGMSG_W(str,...) do { std::wcout << "L[!] LOG MESSAGE :: " << str << std::endl; } while( false )
#else
#define LOGMSG_W(str) do { } while ( false )
#endif


class Pipe
{
public:
	explicit Pipe(const char *);
	~Pipe();
	void createNamedPipe();
	void waitForClient();
	void openNamedPipe();
	void sendMessage(const std::string&);
	int  receiveMessage(std::string&);

private:
	HANDLE hPipe;
	std::string pipename;
	int createSecurityAttributes(SECURITY_ATTRIBUTES*);

};
