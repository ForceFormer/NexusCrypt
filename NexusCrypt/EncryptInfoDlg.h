#pragma once


// CEncryptInfoDlg 대화 상자입니다.

class CEncryptInfoDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CEncryptInfoDlg)

public:
	CEncryptInfoDlg(CWnd* pParent = NULL);   // 표준 생성자입니다.
	virtual ~CEncryptInfoDlg();

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ENCRYPT_INFO };
#endif

private:
	CString m_address;
	CString m_privateKey;
	BOOL m_privateKeyText;

public:
	CString GetAddress() const { return m_address; }
	CString GetPrivateKey() const { return m_privateKey; }
	BOOL GetPrivateKeyText() const { return m_privateKeyText; }

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

	DECLARE_MESSAGE_MAP()
	virtual BOOL OnInitDialog();
};
