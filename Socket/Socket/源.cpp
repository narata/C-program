#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "WS2_32")

#define SOURCE_PORT 7234
#define MAX_RECEIVEBYTE 255

typedef struct ip_hdr //����IP�ײ�
{
	unsigned char h_verlen; //4λ�ײ�����,4λIP�汾��
	unsigned char tos; //8λ��������TOS
	unsigned short total_len; //16λ�ܳ��ȣ��ֽڣ�
	unsigned short ident; //16λ��ʶ
	unsigned short frag_and_flags; //3λ��־λ
	unsigned char ttl; //8λ����ʱ�� TTL
	unsigned char proto; //8λЭ�� (TCP, UDP ������)
	unsigned short checksum; //16λIP�ײ�У���
	unsigned int sourceIP; //32λԴIP��ַ
	unsigned int destIP; //32λĿ��IP��ַ
}IPHEADER;

typedef struct tsd_hdr //����TCPα�ײ�
{
	unsigned long saddr; //Դ��ַ
	unsigned long daddr; //Ŀ�ĵ�ַ
	char mbz;
	char ptcl; //Э������
	unsigned short tcpl; //TCP����
}PSDHEADER;

typedef struct tcp_hdr //����TCP�ײ�
{
	USHORT th_sport; //16λԴ�˿�
	USHORT th_dport; //16λĿ�Ķ˿�
	unsigned int th_seq; //32λ���к�
	unsigned int th_ack; //32λȷ�Ϻ�
	unsigned char th_lenres; //4λ�ײ�����/6λ������
	unsigned char th_flag; //6λ��־λ
	USHORT th_win; //16λ���ڴ�С
	USHORT th_sum; //16λУ���
	USHORT th_urp; //16λ��������ƫ����
}TCPHEADER;

//CheckSum:����У��͵��Ӻ���
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

	/*����һ��ԭʼ�׽���*/
	if ((sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_RAW, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET)
	{
		printf("Socket Setup Error!\n");
		return false;
	}
	flag = true;

	/*����ѡ��ֵ*/
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
	addr_in.sin_port = htons(80);		//�޷��Ŷ�������ת���������ֽ�˳��
	addr_in.sin_addr.S_un.S_addr = inet_addr("219.216.111.250");		//��һ�����ʮ���Ƶ�IPת����һ������������

	//
	//
	//���IP�ײ�
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

	//���TCP�ײ�
	tcpHeader.th_dport = htons(80);
	tcpHeader.th_sport = htons(SOURCE_PORT); //Դ�˿ں�
	tcpHeader.th_seq = htonl(0x12345678);
	tcpHeader.th_ack = 0;
	tcpHeader.th_lenres = (sizeof(tcpHeader) / 4 << 4 | 0);
	tcpHeader.th_flag = 2; //�޸�������ʵ�ֲ�ͬ�ı�־λ̽�⣬2��SYN��1��FIN��16��ACK̽�� �ȵ�
	tcpHeader.th_win = htons(512);
	tcpHeader.th_urp = 0;
	tcpHeader.th_sum = 0;

	//���TCPα�ײ�
	psdHeader.saddr = ipHeader.sourceIP;
	psdHeader.daddr = ipHeader.destIP;
	psdHeader.mbz = 0;
	psdHeader.ptcl = IPPROTO_TCP;
	psdHeader.tcpl = htons(sizeof(tcpHeader));

	//����У���
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