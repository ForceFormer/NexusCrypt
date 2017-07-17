
// NexusCryptDlg.cpp : 구현 파일
//

#include "stdafx.h"
#include "NexusCrypt.h"
#include "NexusCryptDlg.h"
#include "afxdialogex.h"
#include "Util.h"
#include "Keystore.h"
#include "PasswordDlg.h"
#include "EncryptInfoDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 응용 프로그램 정보에 사용되는 CAboutDlg 대화 상자입니다.

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

// 구현입니다.
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CNexusCryptDlg 대화 상자



CNexusCryptDlg::CNexusCryptDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_NEXUSCRYPT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CNexusCryptDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_STATIC_IMAGE, m_image);
	DDX_Control(pDX, IDC_EDIT_KEYFILE_PATH, m_edtKeyfilePath);
}

void CNexusCryptDlg::SetTemporarilyClipboard(const CStringA& str)
{
	KillTimer(Timer_ClearClipboard);

	MessageBox(_T("10초가 지나거나 프로그램이 종료될 때까지 복사됩니다"));

	SetClipboard(str);
	SetTimer(Timer_ClearClipboard, 10 * 1000, nullptr);
}

BEGIN_MESSAGE_MAP(CNexusCryptDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_CLOSE()
	ON_WM_TIMER()
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_BUTTON_KEYFILE_SELECT, &CNexusCryptDlg::OnClickedButtonKeyfileSelect)	
	ON_BN_CLICKED(IDC_BUTTON_DECRYPT, &CNexusCryptDlg::OnClickedButtonDecrypt)
	ON_BN_CLICKED(IDC_BUTTON_ENCRYPT, &CNexusCryptDlg::OnClickedButtonEncrypt)
	ON_BN_CLICKED(IDC_BUTTON_CHANGE_PASSWORD, &CNexusCryptDlg::OnBnClickedButtonChangePassword)
END_MESSAGE_MAP()


// CNexusCryptDlg 메시지 처리기

BOOL CNexusCryptDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 시스템 메뉴에 "정보..." 메뉴 항목을 추가합니다.

	// IDM_ABOUTBOX는 시스템 명령 범위에 있어야 합니다.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 이 대화 상자의 아이콘을 설정합니다.  응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.
	ChangeWindowMessageFilter(WM_DROPFILES, MSGFLT_ADD);
	ChangeWindowMessageFilter(WM_COPYDATA, MSGFLT_ADD);
	ChangeWindowMessageFilter(0x0049, MSGFLT_ADD);

	auto hBmp = (HBITMAP)LoadImage(AfxGetInstanceHandle(), GetRootDirectoryPath() + _T("\\NexusStorm.bmp"), IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
	m_image.SetBitmap(hBmp);

	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

void CNexusCryptDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다.  문서/뷰 모델을 사용하는 MFC 응용 프로그램의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CNexusCryptDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트입니다.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR CNexusCryptDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CNexusCryptDlg::OnClose()
{
	// TODO: 여기에 메시지 처리기 코드를 추가 및/또는 기본값을 호출합니다.
	SetClipboard("");

	CDialogEx::OnClose();
}


void CNexusCryptDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: 여기에 메시지 처리기 코드를 추가 및/또는 기본값을 호출합니다.
	if (nIDEvent == Timer_ClearClipboard)
	{
		KillTimer(nIDEvent);

		SetClipboard("");
	}

	CDialogEx::OnTimer(nIDEvent);
}


void CNexusCryptDlg::OnDropFiles(HDROP hDropInfo)
{
	// TODO: 여기에 메시지 처리기 코드를 추가 및/또는 기본값을 호출합니다.
	CString filename;

	auto count = DragQueryFile(hDropInfo, 0xFFFFFFFF, nullptr, 0);
	filename.ReleaseBuffer();

	for (auto i = 0u; i < count; ++i)
	{
		auto filesize = DragQueryFile(hDropInfo, i, filename.GetBuffer(MAX_PATH), MAX_PATH);
		filename.ReleaseBuffer();

		m_edtKeyfilePath.SetWindowText(filename);
		break;
	}

	CDialogEx::OnDropFiles(hDropInfo);
}


void CNexusCryptDlg::OnClickedButtonKeyfileSelect()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	CString filename;
	m_edtKeyfilePath.GetWindowText(filename);

	OPENFILENAME ofn = { 0 };
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = GetSafeHwnd();
	ofn.lpstrFilter = _T("All files(*.*)\0*.*\0");
	ofn.lpstrFile = filename.GetBufferSetLength(MAX_PATH);
	ofn.nMaxFile = MAX_PATH;
	ofn.nFilterIndex = 0;
	ofn.lpstrFileTitle = nullptr;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = filename.GetBufferSetLength(MAX_PATH);
	ofn.lpstrDefExt = _T("");
	ofn.Flags = OFN_EXPLORER | OFN_ENABLESIZING | OFN_HIDEREADONLY;
	ofn.lpstrTitle = _T("파일 선택");

	auto result = GetOpenFileName(&ofn);
	filename.ReleaseBuffer();

	if (result)
	{
		m_edtKeyfilePath.SetWindowText(filename);
	}
}


void CNexusCryptDlg::OnClickedButtonDecrypt()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	CString filename;
	m_edtKeyfilePath.GetWindowText(filename);

	try
	{
		auto keystore = LoadKeystore((LPCSTR)CStringA(filename));

		std::string password;
		{
			CPasswordDlg dlg;
			auto result = dlg.DoModal();
			if (result == IDCANCEL)
				return;

			password = (LPCSTR)CStringA(dlg.GetPassword());
		}

		auto keyplain = DecryptKeystore(keystore, password);
		SetTemporarilyClipboard(keyplain.key.c_str());
	}
	catch (const std::exception& e)
	{
		MessageBox(CString(e.what()));
		return;
	}
}


void CNexusCryptDlg::OnBnClickedButtonChangePassword()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	CString filename;
	m_edtKeyfilePath.GetWindowText(filename);

	try
	{
		auto keystore = LoadKeystore((LPCSTR)CStringA(filename));

		std::string password;
		{
			CPasswordDlg dlg;
			auto result = dlg.DoModal();
			if (result == IDCANCEL)
				return;

			password = (LPCSTR)CStringA(dlg.GetPassword());
		}

		auto keyplain = DecryptKeystore(keystore, password);

		std::string newPassword;
		{
			CPasswordDlg dlg(_T("비밀번호 변경 - 절대 잊지마세요"));
			auto result = dlg.DoModal();
			if (result == IDCANCEL)
				return;

			newPassword = (LPCSTR)CStringA(dlg.GetPassword());
		}

		std::string newPassword2;
		{
			CPasswordDlg dlg(_T("비밀번호 확인"));
			auto result = dlg.DoModal();
			if (result == IDCANCEL)
				return;

			newPassword2 = (LPCSTR)CStringA(dlg.GetPassword());
		}

		if (newPassword != newPassword2)
		{
			MessageBox(_T("비밀번호가 다릅니다"));
			return;
		}

		keystore = EncryptKeyplain(keyplain, newPassword);
		
		{
			CString filename;

			OPENFILENAME ofn = { 0 };
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = GetSafeHwnd();
			ofn.lpstrFilter = _T("All files(*.*)\0*.*\0");
			ofn.lpstrFile = filename.GetBufferSetLength(MAX_PATH);
			ofn.nMaxFile = MAX_PATH;
			ofn.nFilterIndex = 0;
			ofn.lpstrFileTitle = nullptr;
			ofn.nMaxFileTitle = 0;
			ofn.lpstrInitialDir = filename.GetBufferSetLength(MAX_PATH);
			ofn.lpstrDefExt = _T("");
			ofn.Flags = OFN_EXPLORER | OFN_ENABLESIZING | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
			ofn.lpstrTitle = _T("파일 저장");

			auto result = GetSaveFileName(&ofn);
			filename.ReleaseBuffer();

			if (result == FALSE)
				return;

			SaveKeystore(keystore, (LPCSTR)CStringA(filename));
		}

		MessageBox(_T("변경되었습니다."));
	}
	catch (const std::exception& e)
	{
		MessageBox(CString(e.what()));
		return;
	}
}


void CNexusCryptDlg::OnClickedButtonEncrypt()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.

	try
	{
		Keyplain keyplain;
		{
			CEncryptInfoDlg dlg;
			auto result = dlg.DoModal();
			if (result == IDCANCEL)
				return;

			keyplain.address = (LPCSTR)CStringA(dlg.GetAddress());
			keyplain.key = (LPCSTR)CStringA(dlg.GetPrivateKey());
			if (dlg.GetPrivateKeyText())
				keyplain.keytype = "text";
			
			auto uuid = boost::uuids::random_generator()();
			keyplain.id = boost::uuids::to_string(uuid);
		}

		std::string password;
		{
			CPasswordDlg dlg(_T("비밀번호 변경 - 절대 잊지마세요"));
			auto result = dlg.DoModal();
			if (result == IDCANCEL)
				return;

			password = (LPCSTR)CStringA(dlg.GetPassword());
		}

		std::string password2;
		{
			CPasswordDlg dlg(_T("비밀번호 확인"));
			auto result = dlg.DoModal();
			if (result == IDCANCEL)
				return;

			password2 = (LPCSTR)CStringA(dlg.GetPassword());
		}

		if (password != password2)
		{
			MessageBox(_T("비밀번호가 다릅니다"));
			return;
		}

		auto keystore = EncryptKeyplain(keyplain, password);

		{
			CString filename;

			OPENFILENAME ofn = { 0 };
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = GetSafeHwnd();
			ofn.lpstrFilter = _T("All files(*.*)\0*.*\0");
			ofn.lpstrFile = filename.GetBufferSetLength(MAX_PATH);
			ofn.nMaxFile = MAX_PATH;
			ofn.nFilterIndex = 0;
			ofn.lpstrFileTitle = nullptr;
			ofn.nMaxFileTitle = 0;
			ofn.lpstrInitialDir = filename.GetBufferSetLength(MAX_PATH);
			ofn.lpstrDefExt = _T("");
			ofn.Flags = OFN_EXPLORER | OFN_ENABLESIZING | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
			ofn.lpstrTitle = _T("파일 저장");

			auto result = GetSaveFileName(&ofn);
			filename.ReleaseBuffer();

			if (result == FALSE)
				return;

			SaveKeystore(keystore, (LPCSTR)CStringA(filename));
		}

		MessageBox(_T("생성되었습니다."));
	}
	catch (const std::exception& e)
	{
		MessageBox(CString(e.what()));
		return;
	}	
}




