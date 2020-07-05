#pragma once

#include <iostream>
#include <Windows.h>

using namespace std;

class MyNamedPipe
{
public:
	explicit MyNamedPipe(const char *name);
	~MyNamedPipe();
	
	void openNamedPipe();
	void sendMessage(const string&);
	int receiveMessage(string&);

private:
	HANDLE hPipe;
	string pipename;

};
