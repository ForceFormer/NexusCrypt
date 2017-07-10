// EncryptInfoDlg.cpp : 구현 파일입니다.
//

#include "stdafx.h"
#include "NexusCrypt.h"
#include "EncryptInfoDlg.h"
#include "afxdialogex.h"


// CEncryptInfoDlg 대화 상자입니다.

IMPLEMENT_DYNAMIC(CEncryptInfoDlg, CDialogEx)

CEncryptInfoDlg::CEncryptInfoDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_ENCRYPT_INFO, pParent)
	, m_address(_T(""))
	, m_privateKey(_T(""))
	, m_privateKeyText(FALSE)
{

}

CEncryptInfoDlg::~CEncryptInfoDlg()
{
}

void CEncryptInfoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_ADDRESS, m_address);
	DDX_Text(pDX, IDC_EDIT_PRIVATE_KEY, m_privateKey);
	DDX_Check(pDX, IDC_CHECK_PRIVATE_KEY_TEXT, m_privateKeyText);
}


BEGIN_MESSAGE_MAP(CEncryptInfoDlg, CDialogEx)
END_MESSAGE_MAP()


// CEncryptInfoDlg 메시지 처리기입니다.


BOOL CEncryptInfoDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  여기에 추가 초기화 작업을 추가합니다.
	GetDlgItem(IDC_EDIT_ADDRESS)->SetFocus();

	return FALSE;
}
