#pragma once


// CAdpDlg 对话框

class CAdpDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CAdpDlg)

public:
	CAdpDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CAdpDlg();

// 对话框数据
	enum { IDD = IDD_ADP_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_list1;
	virtual BOOL OnInitDialog();
	afx_msg void OnNMClickList1(NMHDR *pNMHDR, LRESULT *pResult);
	pcap_if_t* GetDevice(void);

private:
	pcap_if_t *alldevs; //所有设备指针
	CString adpname;    // 已选择网卡名称字符串
	pcap_if_t *d;
public:
	afx_msg void OnBnClickedOk();
	pcap_if_t* returnd();
};
