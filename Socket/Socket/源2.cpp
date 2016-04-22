#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "WS2_32")

typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

void main2()
{
	ip_address b;
	char ip_addr[20];
	gets(ip_addr);
	u_int a = inet_addr(ip_addr);
	b.byte1 = a & 0x000000ff;
	b.byte2 = a >> 8 & 0x000000ff;
	b.byte3 = a >> 16 & 0x000000ff;
	b.byte4 = a >> 24 & 0x000000ff;
	printf("%d %d %d %d ", b.byte1,b.byte2,b.byte3,b.byte4);
	getchar();
}