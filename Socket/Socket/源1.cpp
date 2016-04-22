#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Mstcpip.h>
#pragma comment(lib, "WS2_32")

int main1()
{
	SOCKET sniffersock;
	sniffersock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED);

	DWORD lpvBuffer = 1;
	DWORD lpcbBytesReturned = 0;
	WSAIoctl(sniffersock, SIO_RCVALL, &lpvBuffer, sizeof(lpvBuffer), NULL, 0, &lpcbBytesReturned, NULL, NULL);

	char buf[1024] = { 0 };

	//获取链路层的数据包 
	int len;
	while(len = recv(sniffersock, buf, sizeof(buf), true) != -1)
		printf("len = %d\t||%s\n", len,buf);
	getchar();
	return 0;
}
