#pragma once


// CEncryptInfoDlg ��ȭ �����Դϴ�.

class CEncryptInfoDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CEncryptInfoDlg)

public:
	CEncryptInfoDlg(CWnd* pParent = NULL);   // ǥ�� �������Դϴ�.
	virtual ~CEncryptInfoDlg();

// ��ȭ ���� �������Դϴ�.
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
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV �����Դϴ�.

	DECLARE_MESSAGE_MAP()
	virtual BOOL OnInitDialog();
};
