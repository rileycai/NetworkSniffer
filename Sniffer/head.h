#ifndef _HEAD_H
#define _HEAD_H

/* 网络层协议类型 */
#define IP       0x0800          
#define ARP      0x0806          
#define RARP     0x8035 

/* 传输层类型 */
#define ICMP       0x01
#define IGMP       0x02 
#define TCP        0x06
#define EGP        0x08   
#define UDP        0x11 
#define IPv6       0x29
#define OSPF       0x59

/* 应用层类型 */
#define HTTP       0x50
#define DNS        0x35 

/* 6字节的MAC地址 */
typedef struct ethernet_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}ethernet_address;

/* 以太网帧首部 */
typedef struct ethernet_header
{
	ethernet_address daddr;		// 目的MAC地址
	ethernet_address saddr;		// 源MAC地址
	u_short type;				// 协议类型
}ethernet_header;



/* 4字节的IP地址 */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header
{
	u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
	u_char  tos;            // 服务类型(Type of service) 
	u_short tlen;           // 总长(Total length) 
	u_short identification; // 标识(Identification)
	u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char  ttl;            // 生存时间(Time to live)
	u_char  type;           // 协议(Protocol)
	u_short crc;            // 首部校验和(Header checksum)
	ip_address  saddr;      // 源地址(Source address)
	ip_address  daddr;      // 目的地址(Destination address)
	u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

/* ARP 首部 */
typedef struct arp_header
{

	u_short arp_hdr;				//硬件类型：指明了发送方想知道的硬件接口类型，以太网的值为1
	u_short arp_pro;				//协议类型：指明了发送方提供的高层协议类型，IP为0800（16进制）
	u_char arp_hln;					//硬件长度，8位字段，定义对应物理地址长度，以太网中这个值为6
	u_char apr_pln;					//协议长度，8位字段，定义以字节为单位的逻辑地址长度，对IPV4协议这个值为4
	u_short arp_opt;				//操作类型：用来表示这个报文的类型，ARP请求为1，ARP响应为2，RARP请求为3，RARP响应为4
	ethernet_address arp_smac;		//发送端硬件地址，可变长度字段，对以太网这个字段是6字节长
	ip_address arp_sip;				//发送端协议地址，可变长度字段，对IP协议，这个字段是4字节长
	ethernet_address arp_dmac;		//接受端硬件地址
	ip_address arp_dip;				//接收端协议地址
}arp_header;

/* TCP 首部*/
typedef struct tcp_header
{
	u_short sport;          // 源端口(Source port)
	u_short dport;          // 目的端口(Destination port)
	u_int seq;              // 顺序号
	u_int ack;              // 确认号
	u_char len;				// TCP头部长度，数据偏移单位是4字节，这里只用前4位
	u_char flags;			// 后6位分别为：URG，ACK，PSH，RST，SYN，FIN
	u_short win;			// 窗口大小
	u_short crc;			// 校验和
	u_short urp;			// 紧急指针
}tcp_header;

/* UDP 首部*/
typedef struct udp_header
{
	u_short sport;          // 源端口(Source port)
	u_short dport;          // 目的端口(Destination port)
	u_short len;            // UDP报头和UDP数据的长度
	u_short crc;            // 校验和(Checksum)
}udp_header;

/* ICMP 首部*/
typedef struct icmp_header
{
	u_char type;			//类型
	u_char code;			//代码
	u_short checksum;		//校验和
}icmp_header;

/* DNS 首部*/
typedef struct dns_header
{
	u_short identification;     // 标识
	u_short flags;				// 标志
	u_short questions_num;      // 问题数
	u_short answers_num;        // 资源记录数
	u_short authority_num;      //授权资源记录数
	u_short addition_num;		//额外资源记录数
}dns_header;

#endif