// PasswordDlg.cpp : ���� �����Դϴ�.
//

#include "stdafx.h"
#include "NexusCrypt.h"
#include "PasswordDlg.h"
#include "afxdialogex.h"


// CPasswordDlg ��ȭ �����Դϴ�.

IMPLEMENT_DYNAMIC(CPasswordDlg, CDialogEx)

CPasswordDlg::CPasswordDlg(const CString& title, CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_PASSWORD, pParent)
	, m_title(title)
	, m_password(_T(""))
{

}

CPasswordDlg::~CPasswordDlg()
{
}

void CPasswordDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_PASSWORD, m_password);
}


BEGIN_MESSAGE_MAP(CPasswordDlg, CDialogEx)
END_MESSAGE_MAP()


// CPasswordDlg �޽��� ó�����Դϴ�.


BOOL CPasswordDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  ���⿡ �߰� �ʱ�ȭ �۾��� �߰��մϴ�.
	if (m_title.IsEmpty() == FALSE)
		SetWindowText(m_title);

	GetDlgItem(IDC_EDIT_PASSWORD)->SetFocus();

	return FALSE;
}
