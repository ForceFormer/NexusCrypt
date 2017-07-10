// PasswordDlg.cpp : 구현 파일입니다.
//

#include "stdafx.h"
#include "NexusCrypt.h"
#include "PasswordDlg.h"
#include "afxdialogex.h"


// CPasswordDlg 대화 상자입니다.

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


// CPasswordDlg 메시지 처리기입니다.


BOOL CPasswordDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  여기에 추가 초기화 작업을 추가합니다.
	if (m_title.IsEmpty() == FALSE)
		SetWindowText(m_title);

	GetDlgItem(IDC_EDIT_PASSWORD)->SetFocus();

	return FALSE;
}
