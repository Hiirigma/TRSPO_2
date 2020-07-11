#pragma once
#define PIPE_NAME "\\\\.\\pipe\\lab2"
#include <windows.h>
#include <iostream>
#include <string>
using namespace std;

#ifdef _DEBUG
#include <shlobj.h>
#include <fstream>
#define LOG(name) ofstream LOG_FILE;\
char def_path[ _MAX_PATH ];\
string cur_directory_path;\
if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, def_path) == S_OK)\
{\
	cur_directory_path = def_path;\
}\
cur_directory_path +="\\";\
cur_directory_path +=name;\
LOG_FILE.open(cur_directory_path,std::ios_base::app);
#define LOG_W(name) wofstream LOG_FILE;\
char def_path[ _MAX_PATH ];\
string cur_directory_path;\
if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, def_path) == S_OK)\
{\
	cur_directory_path = def_path;\
}\
cur_directory_path +="\\";\
cur_directory_path +=name;\
LOG_FILE.open(cur_directory_path,std::ios_base::app);

#define LOGMSG(str,...) do { LOG_FILE << "LOG MESSAGE :: " << str << std::endl; } while( false )
#define LOGMSG_W(str,...) do { LOG_FILE << L"LOG MESSAGE :: " << str << std::endl; } while( false )

#else
#define LOG(name) 
#define LOG_W(name)
#define LOGMSG(str) do {cout << "LOG MESSAGE :: " << str << std::endl; } while ( false )
#define LOGMSG_W(str) do {wcout << L"LOG MESSAGE :: " << str << std::endl; } while ( false )
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
