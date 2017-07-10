
// NexusCryptDlg.h : ��� ����
//

#pragma once
#include "afxwin.h"


// CNexusCryptDlg ��ȭ ����
class CNexusCryptDlg : public CDialogEx
{
// �����Դϴ�.
public:
	CNexusCryptDlg(CWnd* pParent = NULL);	// ǥ�� �������Դϴ�.

// ��ȭ ���� �������Դϴ�.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_NEXUSCRYPT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV �����Դϴ�.

protected:
	void SetTemporarilyClipboard(const CStringA& str);

private:
	CStatic m_image;
	CEdit m_edtKeyfilePath;

// �����Դϴ�.
protected:
	HICON m_hIcon;

	// ������ �޽��� �� �Լ�
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()	
	afx_msg void OnClose();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnClickedButtonKeyfileSelect();
	afx_msg void OnClickedButtonDecrypt();
	afx_msg void OnBnClickedButtonChangePassword();
	afx_msg void OnClickedButtonEncrypt();
};
