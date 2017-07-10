
// NexusCryptDlg.cpp : ���� ����
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


// ���� ���α׷� ������ ���Ǵ� CAboutDlg ��ȭ �����Դϴ�.

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// ��ȭ ���� �������Դϴ�.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV �����Դϴ�.

// �����Դϴ�.
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


// CNexusCryptDlg ��ȭ ����



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

	MessageBox(_T("10�ʰ� �����ų� ���α׷��� ����� ������ ����˴ϴ�"));

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


// CNexusCryptDlg �޽��� ó����

BOOL CNexusCryptDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// �ý��� �޴��� "����..." �޴� �׸��� �߰��մϴ�.

	// IDM_ABOUTBOX�� �ý��� ��� ������ �־�� �մϴ�.
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

	// �� ��ȭ ������ �������� �����մϴ�.  ���� ���α׷��� �� â�� ��ȭ ���ڰ� �ƴ� ��쿡��
	//  �����ӿ�ũ�� �� �۾��� �ڵ����� �����մϴ�.
	SetIcon(m_hIcon, TRUE);			// ū �������� �����մϴ�.
	SetIcon(m_hIcon, FALSE);		// ���� �������� �����մϴ�.

	// TODO: ���⿡ �߰� �ʱ�ȭ �۾��� �߰��մϴ�.
	ChangeWindowMessageFilter(WM_DROPFILES, MSGFLT_ADD);
	ChangeWindowMessageFilter(WM_COPYDATA, MSGFLT_ADD);
	ChangeWindowMessageFilter(0x0049, MSGFLT_ADD);

	auto hBmp = (HBITMAP)LoadImage(AfxGetInstanceHandle(), GetRootDirectoryPath() + _T("\\NexusStorm.bmp"), IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
	m_image.SetBitmap(hBmp);

	return TRUE;  // ��Ŀ���� ��Ʈ�ѿ� �������� ������ TRUE�� ��ȯ�մϴ�.
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

// ��ȭ ���ڿ� �ּ�ȭ ���߸� �߰��� ��� �������� �׸�����
//  �Ʒ� �ڵ尡 �ʿ��մϴ�.  ����/�� ���� ����ϴ� MFC ���� ���α׷��� ��쿡��
//  �����ӿ�ũ���� �� �۾��� �ڵ����� �����մϴ�.

void CNexusCryptDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // �׸��⸦ ���� ����̽� ���ؽ�Ʈ�Դϴ�.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Ŭ���̾�Ʈ �簢������ �������� ����� ����ϴ�.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// �������� �׸��ϴ�.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// ����ڰ� �ּ�ȭ�� â�� ���� ���ȿ� Ŀ���� ǥ�õǵ��� �ý��ۿ���
//  �� �Լ��� ȣ���մϴ�.
HCURSOR CNexusCryptDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CNexusCryptDlg::OnClose()
{
	// TODO: ���⿡ �޽��� ó���� �ڵ带 �߰� ��/�Ǵ� �⺻���� ȣ���մϴ�.
	SetClipboard("");

	CDialogEx::OnClose();
}


void CNexusCryptDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: ���⿡ �޽��� ó���� �ڵ带 �߰� ��/�Ǵ� �⺻���� ȣ���մϴ�.
	if (nIDEvent == Timer_ClearClipboard)
	{
		KillTimer(nIDEvent);

		SetClipboard("");
	}

	CDialogEx::OnTimer(nIDEvent);
}


void CNexusCryptDlg::OnDropFiles(HDROP hDropInfo)
{
	// TODO: ���⿡ �޽��� ó���� �ڵ带 �߰� ��/�Ǵ� �⺻���� ȣ���մϴ�.
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
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
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
	ofn.lpstrTitle = _T("���� ����");

	auto result = GetOpenFileName(&ofn);
	filename.ReleaseBuffer();

	if (result)
	{
		m_edtKeyfilePath.SetWindowText(filename);
	}
}


void CNexusCryptDlg::OnClickedButtonDecrypt()
{
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
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
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
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
			CPasswordDlg dlg(_T("��й�ȣ ���� - ���� ����������"));
			auto result = dlg.DoModal();
			if (result == IDCANCEL)
				return;

			newPassword = (LPCSTR)CStringA(dlg.GetPassword());
		}

		std::string newPassword2;
		{
			CPasswordDlg dlg(_T("��й�ȣ Ȯ��"));
			auto result = dlg.DoModal();
			if (result == IDCANCEL)
				return;

			newPassword2 = (LPCSTR)CStringA(dlg.GetPassword());
		}

		if (newPassword != newPassword2)
		{
			MessageBox(_T("��й�ȣ�� �ٸ��ϴ�"));
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
			ofn.lpstrTitle = _T("���� ����");

			auto result = GetSaveFileName(&ofn);
			filename.ReleaseBuffer();

			if (result == FALSE)
				return;

			SaveKeystore(keystore, (LPCSTR)CStringA(filename));
		}

		MessageBox(_T("����Ǿ����ϴ�."));
	}
	catch (const std::exception& e)
	{
		MessageBox(CString(e.what()));
		return;
	}
}


void CNexusCryptDlg::OnClickedButtonEncrypt()
{
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.

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
			CPasswordDlg dlg(_T("��й�ȣ ���� - ���� ����������"));
			auto result = dlg.DoModal();
			if (result == IDCANCEL)
				return;

			password = (LPCSTR)CStringA(dlg.GetPassword());
		}

		std::string password2;
		{
			CPasswordDlg dlg(_T("��й�ȣ Ȯ��"));
			auto result = dlg.DoModal();
			if (result == IDCANCEL)
				return;

			password2 = (LPCSTR)CStringA(dlg.GetPassword());
		}

		if (password != password2)
		{
			MessageBox(_T("��й�ȣ�� �ٸ��ϴ�"));
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
			ofn.lpstrTitle = _T("���� ����");

			auto result = GetSaveFileName(&ofn);
			filename.ReleaseBuffer();

			if (result == FALSE)
				return;

			SaveKeystore(keystore, (LPCSTR)CStringA(filename));
		}

		MessageBox(_T("�����Ǿ����ϴ�."));
	}
	catch (const std::exception& e)
	{
		MessageBox(CString(e.what()));
		return;
	}	
}




