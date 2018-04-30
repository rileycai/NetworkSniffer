// FilterDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Sniffer.h"
#include "FilterDlg.h"
#include "afxdialogex.h"


// CFilterDlg 对话框

IMPLEMENT_DYNAMIC(CFilterDlg, CDialogEx)

CFilterDlg::CFilterDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CFilterDlg::IDD, pParent)
	, filtername(_T(""))
{

}

CFilterDlg::~CFilterDlg()
{
}

void CFilterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_CHECK1, m_tcp);
	DDX_Control(pDX, IDC_CHECK2, m_udp);
	DDX_Control(pDX, IDC_CHECK3, m_arp);
	DDX_Control(pDX, IDC_CHECK4, m_rarp);
	DDX_Control(pDX, IDC_CHECK5, m_icmp);
	DDX_Control(pDX, IDC_CHECK6, m_igmp);
}


BEGIN_MESSAGE_MAP(CFilterDlg, CDialogEx)
	ON_BN_CLICKED(IDOK, &CFilterDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CFilterDlg 消息处理程序


BOOL CFilterDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	// TODO:  在此添加额外的初始化

	m_tcp.SetCheck(1);   
	m_udp.SetCheck(1);   
	m_arp.SetCheck(1);   
	m_rarp.SetCheck(1);   
	m_icmp.SetCheck(1);
	m_igmp.SetCheck(1);

	return TRUE;  // return TRUE unless you set the focus to a control
	// 异常: OCX 属性页应返回 FALSE
}


void CFilterDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	if (1 == m_tcp.GetCheck())   
	{   
		filtername += _T("(tcp and ip) or ");   
	}   
	if (1 == m_udp.GetCheck())   
	{   
		filtername += _T("(udp and ip) or ");   
	}   
	if (1 == m_arp.GetCheck())   
	{   
		filtername += _T("arp or ");   
	}    
	if (1 == m_rarp.GetCheck())   
	{   
		filtername += _T("rarp or ");   
	}   
	if (1 == m_icmp.GetCheck())   
	{   
		filtername += _T("(icmp and ip) or ");   
	} 
	if (1 == m_igmp.GetCheck())   
	{   
		filtername += _T("(igmp and ip) or ");   
	}  
	
	filtername = filtername.Left(filtername.GetLength()-4);  //注意去掉最后多余的" or ",否则过滤规则不成立

	CDialogEx::OnOK();

}

CString CFilterDlg::GetFilterName(void)
{
	return filtername;
}
