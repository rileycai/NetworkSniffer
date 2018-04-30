
// SnifferDlg.h : 头文件
//

#pragma once


// CSnifferDlg 对话框
class CSnifferDlg : public CDialogEx
{
// 构造
public:
	CSnifferDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_SNIFFER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_list1;
	CTreeCtrl m_tree1;
	CEdit m_edit1;
	afx_msg void OnAdp();
	afx_msg void OnHelp();
	afx_msg void OnFilter();
	afx_msg void OnStart();
	pcap_if_t *m_pDevice;
	bool m_bFlag;
	char m_filtername[1024];
	void ShowPacketList(const pcap_pkthdr *pkt_header, const u_char *pkt_data);
	void ShowPacketTree(const pcap_pkthdr *pkt_header, const u_char *pkt_data,long index);
private:
	CArray<const struct pcap_pkthdr *,const struct pcap_pkthdr *>  m_pktHeaders;
	CArray<const u_char *,const u_char *>  m_pktDatas; 
	long m_tcpCount;
	long m_udpCount;
	long m_arpCount;
	long m_icmpCount;
	long m_igmpCount;
	long m_totalCount;
	long m_httpCount;
	long m_dnsCount;
	long m_wangCount;
	long m_qqCount;
	long m_msnCount;
	long m_ucCount;
	long m_talkCount;
	long m_maoxianCount;
	
public:
	afx_msg void OnStop();
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);
	CString m_tcpnum;
	CString m_udpnum;
	CString m_arpnum;
	CString m_icmpnum;
	CString m_igmpnum;
	CString m_totalnum;
	void ShowPckNum();
	afx_msg void OnExit();
	CString m_httpnum;
	CString m_dnsnum;
	CString m_wangnum;
	CString m_qqnum;
	CString m_msnnum;
	CString m_ucnum;
	CString m_talknum;
	CString m_maoxiannum;
};
