#pragma once

CString GetLastErrorMessage(DWORD id);

CString GetRootDirectoryPath();

bool SetClipboard(const CStringA& str);