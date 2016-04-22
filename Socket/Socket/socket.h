#define URG 0x20
#define ACK 0x10
#define PSH 0x08
#define RST 0x04
#define SYN 0x02
#define FIN 0x01

/*定义IP首部*/
typedef struct _iphdr
{
	unsigned char h_verlen;			//8位  版本号（4）+首部长度（4）
	unsigned char type;				//8位  服务类型
	unsigned short total_len;		//16位 总长度（字节）
	unsigned short ident;			//16位 重组标识
	unsigned short frag;			//16位 标志位（3）+段偏移量（13）
	unsigned char ttl;				//8位  生存时间 TTL
	unsigned char protocol;			//8位  协议 (TCP, UDP 或其他)
	unsigned short checksum;		//16位 IP首部校验和
	unsigned int source_ip;			//32位 源IP地址
	unsigned int destination_ip;	//32位 目的IP地址
}IP_HEADER;

/*定义TCP首部*/
typedef struct _tcphdr
{
	unsigned short th_sport;		//16位 源端口
	unsigned short th_dport;		//16位 目的端口
	unsigned int th_seq;			//32位 序列号
	unsigned int th_ack;			//32位 确认号
	unsigned char th_lenres;		//4位  首部长度/6位保留字
	unsigned char th_flag;			//6位  标志位
	unsigned short th_win;			//16位 窗口大小
	unsigned short th_sum;			//16位 校验和
	unsigned short th_urp;			//16位 紧急数据偏移量
}TCP_HEADER;

/*定义TCP伪首部*/
typedef struct psd_hdr //定义TCP伪首部
{
	unsigned long saddr;	//源地址
	unsigned long daddr;	//目的地址
	char mbz;
	char ptcl;				//协议类型
	unsigned short tcpl;	//TCP长度
}PSD_HEADER;

/*定义ICMP首部*/
typedef struct icmp_hdr
{
	unsigned char  i_type;           // 类型
	unsigned char  i_code;           // 代码
	unsigned short i_cksum;          // 校验码
	unsigned short i_id;             // 非标准的ICMP首部  
	unsigned short i_seq;
	unsigned long  timestamp;
}ICMP_HEADER;

/*定义UDP首部*/
typedef struct udp_hdr
{
	unsigned short uh_sport;
	unsigned short uh_dport;
	unsigned short uh_len;
	unsigned short uh_sum;
}UDP_HEADER;

/*计算校验和*/
unsigned short checksum(unsigned short *buffer, int size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		cksum += *(unsigned short*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}
