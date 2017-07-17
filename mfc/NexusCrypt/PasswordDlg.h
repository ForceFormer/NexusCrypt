#pragma once


// CPasswordDlg ��ȭ �����Դϴ�.

class CPasswordDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CPasswordDlg)

public:
	CPasswordDlg(const CString& title = _T(""), CWnd* pParent = NULL);   // ǥ�� �������Դϴ�.
	virtual ~CPasswordDlg();

// ��ȭ ���� �������Դϴ�.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PASSWORD };
#endif

private:
	CString m_title;
	CString m_password;

public:
	CString GetPassword() const { return m_password; }

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV �����Դϴ�.

	DECLARE_MESSAGE_MAP()	
	virtual BOOL OnInitDialog();
};
