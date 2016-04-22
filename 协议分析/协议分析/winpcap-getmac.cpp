#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>
#include <remote-ext.h>
#include <conio.h>
#include "packet32.h"
#include <iphlpapi.h>
#include <ntddndis.h>
#include "header.h"

/* 获得本机mac地址 */
int get_local_mac(u_char * adaptername, u_char *localmac)
{
#define Max_Num_Adapter 10
	char AdapterList[Max_Num_Adapter][1024];
	LPADAPTER	lpAdapter = 0;
	int			i = 0;
	DWORD		dwErrorCode;
	char		AdapterName[8192];
	char		*temp, *temp1;
	int			AdapterNum = 0;
	ULONG		AdapterLength;
	PPACKET_OID_DATA  OidData;
	BOOLEAN		Status;

	AdapterLength = sizeof(AdapterName);

	if (PacketGetAdapterNames(AdapterName, &AdapterLength) == FALSE){
		printf("Unable to retrieve the list of the adapters!\n");
		return -1;
	}
	temp = AdapterName;
	temp1 = AdapterName;

	/* 将网络适配器名称存储到AdapterList数组中 */
	while ((*temp != '\0') || (*(temp - 1) != '\0'))
	{
		if (*temp == '\0')
		{
			memcpy(AdapterList[i], temp1, temp - temp1);
			AdapterList[i][temp - temp1] = '\0';
			temp1 = temp + 1;
			i++;
		}
		temp++;
	}

	/* Open the selected adapter */
	AdapterNum = i;	//网络适配器数量
	for (int i = 0; i < AdapterNum; i++)
	{
		if (memcmp(AdapterList[i], adaptername + 8, strlen((char *)adaptername) - 8) == 0)
		{
			lpAdapter = PacketOpenAdapter(AdapterList[i]);
			break;
		}
	}

	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		dwErrorCode = GetLastError();
		printf("Unable to open the adapter, Error Code : %lx\n", dwErrorCode);

		return -1;
	}

	/* Allocate a buffer to get the MAC adress */
	OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
	if (OidData == NULL)
	{
		printf("error allocating memory!\n");
		PacketCloseAdapter(lpAdapter);
		return -1;
	}

	/* Retrieve the adapter MAC querying the NIC driver */
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;

	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);
	Status = PacketRequest(lpAdapter, FALSE, OidData);
	if (Status)
	{
		localmac[0] = (OidData->Data)[0];
		localmac[1] = (OidData->Data)[1];
		localmac[2] = (OidData->Data)[2];
		localmac[3] = (OidData->Data)[3];
		localmac[4] = (OidData->Data)[4];
		localmac[5] = (OidData->Data)[5];
		return 1;
	}
	else
	{
		return -1;
	}

}