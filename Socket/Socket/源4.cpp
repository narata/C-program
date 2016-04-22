#include <winsock2.h>
#include <Iphlpapi.h>
#include <stdio.h>

void byte2Hex(unsigned char bData, unsigned char hex[])
{
	int high = bData / 16, low = bData % 16;
	hex[0] = (high <10) ? ('0' + high) : ('A' + high - 10);
	hex[1] = (low <10) ? ('0' + low) : ('A' + low - 10);
}

int getLocalMac(unsigned char *mac) //获取本机MAC址 
{
	ULONG ulSize = 0;
	PIP_ADAPTER_INFO pInfo = NULL;
	int temp = 0;
	temp = GetAdaptersInfo(pInfo, &ulSize);//第一处调用，获取缓冲区大小
	pInfo = (PIP_ADAPTER_INFO)malloc(ulSize);
	temp = GetAdaptersInfo(pInfo, &ulSize);

	int iCount = 0;
	while (pInfo)//遍历每一张网卡
	{
		//  pInfo->Address MAC址
		for (int i = 0; i<(int)pInfo->AddressLength; i++)
		{
			byte2Hex(pInfo->Address[i], &mac[iCount]);
			iCount += 2;
			if (i<(int)pInfo->AddressLength - 1)
			{
				mac[iCount++] = ':';
			}
			else
			{
				mac[iCount++] = '#';
			}
		}
		puts(pInfo->AdapterName);
		printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", pInfo->Address[0], pInfo->Address[1], pInfo->Address[2], pInfo->Address[3], pInfo->Address[4], pInfo->Address[5]);
		puts(pInfo->IpAddressList.IpAddress.String);
		puts(pInfo->IpAddressList.IpMask.String);
		puts(pInfo->GatewayList.IpAddress.String);
		pInfo = pInfo->Next;
	}

	if (iCount >0)
	{
		mac[--iCount] = '\0';
		return iCount;
	}
	else return -1;
}

int main4(int argc, char* argv[])
{
	/*unsigned char address[1024];
	if (getLocalMac(address)>0)
	{
		printf("mac-%s\n", address);
	}
	else
	{
		printf("invoke getMAC error!\n");
	}*/
	MIB_IPNETTABLE *ipNetTable = NULL;
	ULONG size = 0;
	DWORD result = 0;
	result = GetIpNetTable(ipNetTable, &size, TRUE);
	ipNetTable = (MIB_IPNETTABLE *)malloc(size);
	result = GetIpNetTable(ipNetTable, &size, TRUE);
	if (result)
	{
		printf("GetIpNetTable error\n");
		exit(1);
	}
	IN_ADDR ip;
	for (int i = 0; i < ipNetTable->dwNumEntries; i++)
	{
		if (inet_addr("202.118.19.254") == ipNetTable->table[i].dwAddr)
		{
			for (int j = 0; j < 6; j++)
			{
				printf("%.2x", ipNetTable->table[i].bPhysAddr[j]);
				if (j != 5)
				{
					printf("-");
				}
			}
			break;
		}
	}
	getchar();
	return 0;
}