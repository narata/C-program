#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "WS2_32")

#define SOURCE_PORT 7234
#define MAX_RECEIVEBYTE 255

typedef struct ip_hdr //定义IP首部
{
	unsigned char h_verlen; //4位首部长度,4位IP版本号
	unsigned char tos; //8位服务类型TOS
	unsigned short total_len; //16位总长度（字节）
	unsigned short ident; //16位标识
	unsigned short frag_and_flags; //3位标志位
	unsigned char ttl; //8位生存时间 TTL
	unsigned char proto; //8位协议 (TCP, UDP 或其他)
	unsigned short checksum; //16位IP首部校验和
	unsigned int sourceIP; //32位源IP地址
	unsigned int destIP; //32位目的IP地址
}IPHEADER;

typedef struct tsd_hdr //定义TCP伪首部
{
	unsigned long saddr; //源地址
	unsigned long daddr; //目的地址
	char mbz;
	char ptcl; //协议类型
	unsigned short tcpl; //TCP长度
}PSDHEADER;

typedef struct tcp_hdr //定义TCP首部
{
	USHORT th_sport; //16位源端口
	USHORT th_dport; //16位目的端口
	unsigned int th_seq; //32位序列号
	unsigned int th_ack; //32位确认号
	unsigned char th_lenres; //4位首部长度/6位保留字
	unsigned char th_flag; //6位标志位
	USHORT th_win; //16位窗口大小
	USHORT th_sum; //16位校验和
	USHORT th_urp; //16位紧急数据偏移量
}TCPHEADER;

//CheckSum:计算校验和的子函数
USHORT checksum(USHORT *buffer, int size)
{
	unsigned long cksum = 0;
	while (size >1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

void useage()
{
	printf("******************************************\n");
	printf("TCPPing\n");
	printf("\t Written by Refdom\n");
	printf("\t Email: refdom@263.net/n");
	printf("Useage: TCPPing.exe Target_ip Target_port\n");
	printf("*******************************************\n");
}

int main0(int argc, char* argv[])
{
	WSADATA WSAData;
	SOCKET sock;
	SOCKADDR_IN addr_in;
	IPHEADER ipHeader;
	TCPHEADER tcpHeader;
	PSDHEADER psdHeader;

	char szSendBuf[60] = { 0 };
	BOOL flag;
	int rect, nTimeOver;

	useage();


	if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0)
	{
		printf("WSAStartup Error!\n");
		return false;
	}

	/*创建一个原始套接字*/
	if ((sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_RAW, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET)
	{
		printf("Socket Setup Error!\n");
		return false;
	}
	flag = true;

	/*设置选项值*/
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&flag, sizeof(flag)) == SOCKET_ERROR)
	{
		printf("setsockopt IP_HDRINCL error!\n");
		return false;
	}
	nTimeOver = 1000;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&nTimeOver, sizeof(nTimeOver)) == SOCKET_ERROR)
	{
		printf("setsockopt SO_SNDTIMEO error!\n");
		return false;
	}
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(80);		//无符号短整形数转换成网络字节顺序
	addr_in.sin_addr.S_un.S_addr = inet_addr("219.216.111.250");		//将一个点分十进制的IP转换成一个长整数型数

	//
	//
	//填充IP首部
	ipHeader.h_verlen = (4 << 4 | sizeof(ipHeader) / sizeof(unsigned long));
	// ipHeader.tos=0;
	ipHeader.total_len = htons(sizeof(ipHeader)+sizeof(tcpHeader));
	ipHeader.ident = 1;
	ipHeader.frag_and_flags = 0;
	ipHeader.ttl = 128;
	ipHeader.proto = IPPROTO_TCP;
	ipHeader.checksum = 0;
	ipHeader.sourceIP = inet_addr("202.118.19.183");
	ipHeader.destIP = inet_addr("219.216.111.250");

	//填充TCP首部
	tcpHeader.th_dport = htons(80);
	tcpHeader.th_sport = htons(SOURCE_PORT); //源端口号
	tcpHeader.th_seq = htonl(0x12345678);
	tcpHeader.th_ack = 0;
	tcpHeader.th_lenres = (sizeof(tcpHeader) / 4 << 4 | 0);
	tcpHeader.th_flag = 2; //修改这里来实现不同的标志位探测，2是SYN，1是FIN，16是ACK探测 等等
	tcpHeader.th_win = htons(512);
	tcpHeader.th_urp = 0;
	tcpHeader.th_sum = 0;

	//填充TCP伪首部
	psdHeader.saddr = ipHeader.sourceIP;
	psdHeader.daddr = ipHeader.destIP;
	psdHeader.mbz = 0;
	psdHeader.ptcl = IPPROTO_TCP;
	psdHeader.tcpl = htons(sizeof(tcpHeader));

	//计算校验和
	memcpy(szSendBuf, &psdHeader, sizeof(psdHeader));
	memcpy(szSendBuf + sizeof(psdHeader), &tcpHeader, sizeof(tcpHeader));
	tcpHeader.th_sum = checksum((USHORT *)szSendBuf, sizeof(psdHeader)+sizeof(tcpHeader));

	memcpy(szSendBuf, &ipHeader, sizeof(ipHeader));
	memcpy(szSendBuf + sizeof(ipHeader), &tcpHeader, sizeof(tcpHeader));
	memset(szSendBuf + sizeof(ipHeader)+sizeof(tcpHeader), 0, 4);
	ipHeader.checksum = checksum((USHORT *)szSendBuf, sizeof(ipHeader)+sizeof(tcpHeader));

	memcpy(szSendBuf, &ipHeader, sizeof(ipHeader));

	rect = sendto(sock, szSendBuf, sizeof(ipHeader)+sizeof(tcpHeader),
		0, (struct sockaddr*)&addr_in, sizeof(addr_in));
	if (rect == SOCKET_ERROR)
	{
		printf("send error!:%d\n", WSAGetLastError());
		return false;
	}
	else
		printf("send ok!%d\n",rect);

	closesocket(sock);
	WSACleanup();
	return 0;
}