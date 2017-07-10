#include "stdafx.h"
#include "Util.h"

CString GetLastErrorMessage(DWORD id)
{
	LPTSTR buffer = nullptr;

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
					nullptr,
					id,
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
					(LPTSTR)&buffer,
					0,
					nullptr);
  
	CString message = buffer;
	LocalFree(buffer);

	return message;
}

CString GetRootDirectoryPath()
{
	CString path;
	GetModuleFileName(NULL, path.GetBuffer(MAX_PATH), MAX_PATH);
	path.ReleaseBuffer();

	auto position = path.ReverseFind(_T('\\'));
	if (position >= 0)
		path = path.Left(position);

	return path;
}

bool SetClipboard(const CStringA& str)
{
	if (OpenClipboard(NULL) == FALSE)
		return false;

	EmptyClipboard();

	auto hGlobal = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, str.GetLength() + 1);
	if (hGlobal == NULL)
	{
		CloseClipboard();
		return false;
	}

	auto buffer = (LPSTR)GlobalLock(hGlobal);
	CopyMemory(buffer, (LPCSTR)str, str.GetLength());
	buffer[str.GetLength()] = '\0';
	GlobalUnlock(hGlobal);

	SetClipboardData(CF_TEXT, hGlobal);

	CloseClipboard();

	return true;
}