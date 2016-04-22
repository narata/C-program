#include<stdio.h>  
#include<winsock2.h>  
#pragma comment(lib,"ws2_32.lib") // ¾²Ì¬¿â  

void getIPs()
{
	WORD v = MAKEWORD(1, 1);
	WSADATA wsaData;
	WSAStartup(v, &wsaData); // ¼ÓÔØÌ×½Ó×Ö¿â    

	int i = 0;
	struct hostent *phostinfo = gethostbyname("");
	for (i = 0; NULL != phostinfo&& NULL != phostinfo->h_addr_list[i]; ++i)
	{
		char *pszAddr = inet_ntoa(*(struct in_addr *)phostinfo->h_addr_list[i]);
		printf("%s\n", pszAddr);
	}

	WSACleanup();
}

int main3()
{
	getIPs();
	getchar();
	return 0;
}