#pragma once


// CPasswordDlg 대화 상자입니다.

class CPasswordDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CPasswordDlg)

public:
	CPasswordDlg(const CString& title = _T(""), CWnd* pParent = NULL);   // 표준 생성자입니다.
	virtual ~CPasswordDlg();

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PASSWORD };
#endif

private:
	CString m_title;
	CString m_password;

public:
	CString GetPassword() const { return m_password; }

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

	DECLARE_MESSAGE_MAP()	
	virtual BOOL OnInitDialog();
};
