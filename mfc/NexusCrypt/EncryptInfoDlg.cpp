// EncryptInfoDlg.cpp : ���� �����Դϴ�.
//

#include "stdafx.h"
#include "NexusCrypt.h"
#include "EncryptInfoDlg.h"
#include "afxdialogex.h"


// CEncryptInfoDlg ��ȭ �����Դϴ�.

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


// CEncryptInfoDlg �޽��� ó�����Դϴ�.


BOOL CEncryptInfoDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  ���⿡ �߰� �ʱ�ȭ �۾��� �߰��մϴ�.
	GetDlgItem(IDC_EDIT_ADDRESS)->SetFocus();

	return FALSE;
}
