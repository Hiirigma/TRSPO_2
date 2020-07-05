#include <iostream>
#include <windows.h>
#include <string>
#include "FileHiding.h"

string  fullpath, path, filename;
wstring wfullpath, wpath, wfilename;
bool isPathToHiddenFile = false;
std::string	 FullPath;
std::string	 Path;
std::string	 FileName;
std::wstring WFull_Path;
std::wstring WPath;

HANDLE(WINAPI* pCreateFileA) (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileA;
HANDLE(WINAPI* pCreateFileW) (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;
HANDLE(WINAPI* pFindFirstFileW) (LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) = FindFirstFileW;
HANDLE(WINAPI* pFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) = FindFirstFileA;
BOOL(WINAPI* pFindNextFileW) (HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) = FindNextFileW;
BOOL(WINAPI* pFindNextFileA) (HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) = FindNextFileA;
HANDLE(WINAPI* pFindFirstFileExA) (LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData,
	FINDEX_SEARCH_OPS  fSearchOp, LPVOID  lpSearchFilter, DWORD dwAdditionalFlags) = FindFirstFileExA;
HANDLE(WINAPI* pFindFirstFileExW) (LPCWSTR  lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID  lpFindFileData,
	FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD   dwAdditionalFlags) = FindFirstFileExW;

HANDLE WINAPI MyCreateFileA_withHide(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	if (lpFileName == FullPath)
	{
		return INVALID_HANDLE_VALUE;
	}
	return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyCreateFileW_withHide(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	if (lpFileName == WFull_Path)
	{
		return INVALID_HANDLE_VALUE;
	}
	return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyFindFirstFileA_withHide(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
	if (lpFileName == FullPath)
	{
		return INVALID_HANDLE_VALUE;
	}
	return pFindFirstFileA(lpFileName, lpFindFileData);
}

HANDLE WINAPI MyFindFirstFileW_withHide(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
{
	if (lpFileName == WFull_Path)
	{
		return INVALID_HANDLE_VALUE;
	}
	return pFindFirstFileW(lpFileName, lpFindFileData);
}

BOOL WINAPI MyFindNextFileA_withHide(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
	bool ret = pFindNextFileA(hFindFile, lpFindFileData);
	if (lpFindFileData->cFileName == FullPath)
	{
		ret = pFindNextFileA(hFindFile, lpFindFileData);
	}
	return ret;
}

BOOL WINAPI MyFindNextFileW_withHide(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
	bool ret = pFindNextFileW(hFindFile, lpFindFileData);
	if (lpFindFileData->cFileName == WFull_Path)
	{
		ret = pFindNextFileW(hFindFile, lpFindFileData);
	}
	return ret;
}

HANDLE MyFindFirstFileExW_withHide(LPCWSTR a0, FINDEX_INFO_LEVELS a1, LPWIN32_FIND_DATAW a2, FINDEX_SEARCH_OPS a3, LPVOID a4, DWORD a5)
{
	HANDLE ret = pFindFirstFileExW(a0, a1, a2, a3, a4, a5);
	if (a2->cFileName == WFull_Path)
	{
		ret = INVALID_HANDLE_VALUE;
	}
	return ret;
}

HANDLE MyFindFirstFileExA_withHide(LPCSTR a0, FINDEX_INFO_LEVELS a1, LPWIN32_FIND_DATAA a2, FINDEX_SEARCH_OPS a3, LPVOID a4, DWORD a5)
{
	HANDLE ret = pFindFirstFileExA(a0, a1, a2, a3, a4, a5);
	if (a2->cFileName == FullPath)
	{
		pFindNextFileA(ret, a2);
	}
	return ret;
}


void setPathsToFile(const string& fileName_)
{
	std::size_t backslashPosition = fileName_.rfind('\\');

	FullPath = fileName_;
	path = fullpath.substr(0, backslashPosition + 1);
	filename = fullpath.substr(backslashPosition + 1, FullPath.length());

	wfullpath = wstring(fullpath.begin(), FullPath.end());
	wpath = wstring(path.begin(), path.end());
	wfilename = wstring(filename.begin(), filename.end());
}


int hideFile(const string& fileName)
{
	int i;

	setPathsToFile(fileName);
	LONG err = NULL;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pCreateFileA, MyCreateFileA_withHide);
	err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pCreateFileW, MyCreateFileW_withHide);
	err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindFirstFileW, MyFindFirstFileW_withHide);
	err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindFirstFileA, MyFindFirstFileA_withHide);
	err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindNextFileW, MyFindNextFileW_withHide);
	err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindNextFileA, MyFindNextFileA_withHide);
	err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindFirstFileExW, MyFindFirstFileExW_withHide);
	err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindFirstFileExA, MyFindFirstFileExA_withHide);
	err = DetourTransactionCommit();
	if (err != NO_ERROR)
		return -1;
	return 0;
}
