
// NexusCrypt.h : PROJECT_NAME ���� ���α׷��� ���� �� ��� �����Դϴ�.
//

#pragma once

#ifndef __AFXWIN_H__
	#error "PCH�� ���� �� ������ �����ϱ� ���� 'stdafx.h'�� �����մϴ�."
#endif

#include "resource.h"		// �� ��ȣ�Դϴ�.


// CNexusCryptApp:
// �� Ŭ������ ������ ���ؼ��� NexusCrypt.cpp�� �����Ͻʽÿ�.
//

class CNexusCryptApp : public CWinApp
{
public:
	CNexusCryptApp();

// �������Դϴ�.
public:
	virtual BOOL InitInstance();

// �����Դϴ�.

	DECLARE_MESSAGE_MAP()
};

extern CNexusCryptApp theApp;
