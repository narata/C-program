#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>
#include <remote-ext.h>
#include <conio.h>
#include <windows.h>
#include "packet32.h"
#include <iphlpapi.h>
#include <ntddndis.h>
#include "header.h"

/* 全局变量 */
net_info *n_i;

/*check_sum:计算校验和的子函数*/
unsigned short check_sum(u_short *buffer, int size)
{
	unsigned long cksum = 0;
	while (size >1)
	{
		cksum += *buffer++;
		size -= sizeof(u_short);
	}
	if (size)
	{
		cksum += *(u_short*)buffer;
	}

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (u_short)(~cksum);
}

/*组装链路层包头*/
ether_header* build_ethernet_header(u_char *dest_mac, u_char *source_mac, u_short e_type)
{
	ether_header *e_head = (ether_header *)malloc(sizeof(ether_header));
	for (int i = 0; i < ETHER_ADDR_LEN; i++)
		e_head->ether_shost[i] = source_mac[i];
	for (int i = 0; i < ETHER_ADDR_LEN; i++)
		e_head->ether_dhost[i] = dest_mac[i];
	e_head->ether_type = e_type;
	return e_head;
}

/* ip 地址转换 */
ip_address ip_change(char *ip_addr)
{
	ip_address ip;
	int ip_i = inet_addr(ip_addr);
	ip.byte1 = ip_i & 0x000000ff;
	ip.byte2 = ip_i >> 8 & 0x000000ff;
	ip.byte3 = ip_i >> 16 & 0x000000ff;
	ip.byte4 = ip_i >> 24 & 0x000000ff;
	return ip;
}

/* 本机各种信息获取 */
int get_web_info(char *adaptername , net_info *net_info)
{
	#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
	#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	/* variables used to print DHCP time info */

	ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(sizeof (IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 0;
	}
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 0;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			if (strcmp(pAdapter->AdapterName,adaptername) == 0)
			{
				net_info->ip_addr = ip_change(pAdapter->IpAddressList.IpAddress.String);
				net_info->ip_mask = ip_change(pAdapter->IpAddressList.IpMask.String);
				net_info->gate_addr = ip_change(pAdapter->GatewayList.IpAddress.String);
				net_info->gate_mask = ip_change(pAdapter->GatewayList.IpMask.String);
				memcpy(net_info->mac_addr, pAdapter->Address, 6);
				break;
			}
			pAdapter = pAdapter->Next;
		}
	}
	else {
		printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);
		return 0;
	}
	if (get_arp_mac(net_info->gate_addr,net_info->gate_mac) != 1)
	{
		printf("arp ip -> mac error \n");
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);
	return 1;
}

/* 计算next_seq */
u_int get_next_seq(ip_header *i_h,tcp_header *t_h)
{
	u_int data = t_h->th_seq;
	if ((ntohs(t_h->th_len_resv_code) & 0x0002) == 0x0002)
		data = htonl(ntohl(data) + 1);
	if ((ntohs(t_h->th_len_resv_code) & 0x0001) == 0x0001)
		data = htonl(ntohl(data) + 1);
	data = htonl(ntohl(data) + ntohs(i_h->tlen) - (i_h->ver_ihl & 0x0f) * 4 - (ntohs(t_h->th_len_resv_code) >> 12 & 0x000f) * 4);
	return data;
}

/* 计算ack */
u_int get_ack(ip_header *i_h, tcp_header *t_h)
{	
	u_int data = t_h->th_seq;
	if ((ntohs(t_h->th_len_resv_code) & 0x0002) == 0x0002)
		data = htonl(ntohl(data) + 1);
	if ((ntohs(t_h->th_len_resv_code) & 0x0001) == 0x0001)
		data = htonl(ntohl(data) + 1);
	data = htonl(ntohl(data) + ntohs(i_h->tlen) - (i_h->ver_ihl & 0x0f) * 4 - (ntohs(t_h->th_len_resv_code) >> 12 & 0x000f) * 4);
	return data;
}

/* 由ip获得arp表的对应mac地址 
 * -1 : error
 * 0 : not found
 * 1 : successful
 */
int get_arp_mac(ip_address ip_addr, u_char mac[6])
{
	ULONG ip;
	memcpy(&ip, &ip_addr, sizeof(ip_address));
	MIB_IPNETTABLE *ipNetTable = NULL;
	ULONG size = 0;
	DWORD result = 0;
	result = GetIpNetTable(ipNetTable, &size, TRUE);
	ipNetTable = (MIB_IPNETTABLE *)malloc(size);
	result = GetIpNetTable(ipNetTable, &size, TRUE);
	if (result)
	{
		printf("GetIpNetTable error\n");
		return -1;
	}
	for (int i = 0; i < ipNetTable->dwNumEntries; i++)
	{
		if (ip == ipNetTable->table[i].dwAddr)
		{
			memcpy(mac, ipNetTable->table[i].bPhysAddr, ETHER_ADDR_LEN);
			return 1;
		}
	}
	return 0;
}

/* 发送数据包 */
int send_pack(pcap_t *fp, ether_header * e_h, ip_header *i_h, tcp_header *t_h, u_char *data, int size_data,u_int &next_seq,u_int ack)
{
	u_char packet[65535];
	u_int tcp_len = (ntohs(t_h->th_len_resv_code) >> 12 & 0x000f) * 4;
	u_int ip_len = (i_h->ver_ihl & 0x0f) * 4;

	i_h->tlen = htons(ip_len + tcp_len + size_data);
	i_h->identification = htons(ntohs(i_h->identification) + 1);
	i_h->crc = 0;
	t_h->th_seq = next_seq;
	t_h->th_ack = ack;
	t_h->th_sum = 0;


	/* tcp psd header */
	psd_header *p_h = (psd_header *)malloc(sizeof(psd_header));
	memcpy(&p_h->saddr, &i_h->saddr, sizeof(i_h->saddr));
	memcpy(&p_h->daddr, &i_h->daddr, sizeof(i_h->daddr));
	p_h->plh = 0;
	p_h->pro_t = IPPROTO_TCP;
	p_h->len = htons(tcp_len + size_data);

	/* tcp sum = psd_header + tcp_header + data */
	memcpy(packet, p_h, PSD_LEN);
	memcpy(packet + PSD_LEN, t_h, tcp_len);
	memcpy(packet + PSD_LEN + tcp_len, data, size_data);
	if ((PSD_LEN + tcp_len + size_data) % 2 != 0)
	{
		packet[PSD_LEN + tcp_len + size_data] = 0;
	}
	t_h->th_sum = check_sum((u_short *)packet, PSD_LEN + tcp_len + size_data);

	/* ip sum = ip_header */
	memcpy(packet, i_h, ip_len);
	i_h->crc = check_sum((u_short *)packet, ip_len);

	memcpy(packet, e_h, ETHER_LEN);
	memcpy(packet + ETHER_LEN, i_h, ip_len);
	memcpy(packet + ETHER_LEN + ip_len, t_h, tcp_len);
	memcpy(packet + ETHER_LEN + ip_len + tcp_len, data, size_data);

	if (pcap_sendpacket(fp, packet, ETHER_LEN + ip_len + tcp_len + size_data) != 0)
	{
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
		return 0;
	}
	next_seq = get_next_seq(i_h, t_h);
	return 1;
}

/* 捕获数据包 */
const u_char* get_packet(pcap_t *fp, ip_header *i_h,tcp_header *t_h,u_int next_seq,u_int &ack,u_short data)
{
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	ip_header *ih;
	tcp_header *th;

	if (pcap_datalink(fp) != DLT_EN10MB)	// 检查数据链路层，为了简单，我们只考虑以太网
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		return NULL;
	}

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0){
		if (res == 0)	// 超时
			continue;
		ih = (ip_header *)(pkt_data + 14);			// 获得ip头部
		u_int ip_len = (ih->ver_ihl & 0xf) * 4;		// ip头长
		th = (tcp_header *)((u_char*)ih + ip_len);	// 获得tcp头部
		u_int tcp_len = (ntohs(th->th_len_resv_code) >> 12 & 0x000f) * 4;	// tcp头长

		/* 验证数据包 */
		if ((memcmp(&ih->saddr, &i_h->daddr, sizeof(u_int)) == 0) && (memcmp(&ih->daddr, &i_h->saddr, sizeof(u_int)) == 0))  //验证ip地址
		{
			if (th->th_sport == t_h->th_dport && th->th_dport == t_h->th_sport)	//验证端口
			{
				if ((th->th_ack == next_seq) && ((ntohs(th->th_len_resv_code) & 0x00ff) == data))	//验证seq和ack
				{
					ack = get_ack(ih, th);
					break;
				}
			}
		}
	}
	if (res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		return NULL;
	}
	return pkt_data;
}

int main(int argc, char **argv){
	
	char *adaptername;
	pcap_t *fp;
	u_char packet[100];
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int next_seq;
	u_int ack;
	char * dip_addr = "2.55.76.193";

	/* 捕获数据包 */
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;
	struct tm *ltime;
	char timestr[16];
	u_short sport, dport;
	ip_header *ih, *i_h;
	tcp_header *th, *t_h;
	const u_char *buffer;

	/* 获取本地机器设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s\n", ++i, d->name);
	}

	/* 选择网络适配器 */
	int choose;
	scanf("%d", &choose);
	d = alldevs;
	while (--choose)
	{
		d = d->next;
	}
	adaptername = (char *)malloc(strlen(d->name));
	memcpy(adaptername, d->name + 20, strlen(d->name) - 20);
	adaptername[strlen(d->name) - 20] = '\0';
	puts(adaptername);

	/* 获取本机以及网关网络信息 */
	n_i = (net_info *)malloc(sizeof(net_info));
	get_web_info(adaptername,n_i);

	/* 打开输出设备 */
	if ((fp = pcap_open(d->name,  // 设备名
		65535,							// 要捕获的部分 (只捕获前100个字节)
		PCAP_OPENFLAG_PROMISCUOUS,		// 混杂模式
		1000,							// 读超时时间
		NULL,							// 远程机器验证
		errbuf							// 错误缓冲
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
		return 0;
	}

	/* ethernet header */
	u_char dest_mac[6];
	u_char source_mac[6];
	u_short e_type = htons(0x0800);
	u_int buf[3];
	memcpy(buf, &ip_change(dip_addr), sizeof(u_int));
	memcpy(buf + 1, &n_i->ip_mask, sizeof(u_int));
	memcpy(buf + 2, &n_i->ip_addr, sizeof(u_int));
	if ( (buf[0]&buf[1]) == (buf[1]&buf[2]))
	{
		get_arp_mac(ip_change(dip_addr), dest_mac);
	}
	else
	{
		memcpy(dest_mac, n_i->gate_mac, ETHER_ADDR_LEN);
	}
	memcpy(source_mac, n_i->mac_addr, ETHER_ADDR_LEN);
	ether_header *e_h = build_ethernet_header(dest_mac, source_mac, e_type);
	
	/* ip header */
	i_h = (ip_header *)malloc(sizeof(ip_header));
	i_h->ver_ihl = 0x45;
	i_h->tos = 0;
	i_h->tlen = htons(52);
	i_h->identification = htons(13957);
	i_h->flags_fo = htons(0x4000);
	i_h->ttl = 64;
	i_h->proto = IPPROTO_TCP;
	i_h->crc = 0;
	memcpy(&i_h->saddr,&n_i->ip_addr,4);
	i_h->daddr = ip_change(dip_addr);

	/* Tcp header */
	t_h = (tcp_header *)malloc(sizeof(tcp_header));
	t_h->th_sport = htons(28303);
	t_h->th_dport = htons(502);
	t_h->th_seq = 0;
	t_h->th_ack = 0;
	t_h->th_len_resv_code = htons(0x8002);
	t_h->th_window = htons(8192);
	t_h->th_sum = 0;
	t_h->th_urp = 0;
	t_h->option[0] = htonl(0x020405b4);
	t_h->option[1] = htonl(0x01030302);
	t_h->option[2] = htonl(0x01010402);
	
	next_seq = t_h->th_seq;
	ack = t_h->th_ack;
	u_int tcp_len = (ntohs(t_h->th_len_resv_code) >> 12 & 0x000f) * 4;
	u_int ip_len = (i_h->ver_ihl & 0x0f) * 4;

	/* tcp psd header */
	psd_header *p_h = (psd_header *)malloc(sizeof(psd_header));
	memcpy(&p_h->saddr, &i_h->saddr, sizeof(i_h->saddr));
	memcpy(&p_h->daddr, &i_h->daddr, sizeof(i_h->daddr));
	p_h->plh = 0;
	p_h->pro_t = IPPROTO_TCP;
	p_h->len = htons(tcp_len);

/* tcp 三次握手 */
	u_char data[1000];
	int size_data = 0;
	printf("\n---开始 TCP 三次握手！---");
	if (send_pack(fp, e_h, i_h, t_h, data, size_data, next_seq, ack) == 1)
	{
		printf("\n   syn 包发送成功！");
	}
	else
	{
		printf("\n   syn 包发送失败！");
		system("pause");
		return 0;
	}
		

	/* 获取对应于 fin 的 ack 包*/
	if (get_packet(fp, i_h, t_h, next_seq, ack, 0x0012) != NULL)
	{
		printf("\n   ack包 捕获成功！");
	}
	else
	{
		printf("\n   ack 包捕获失败！");
		system("pause");
		return 0;
	}
		

	/* 发送 ack 包 */
	t_h->th_len_resv_code = htons(0x5010);
	if (send_pack(fp, e_h, i_h, t_h, data, size_data, next_seq, ack) == 1)
	{
		printf("\n   ack包发送成功!");
		printf("\n---TCP连接成功！---");
	}	
	else
	{
		printf("\n   ack包发送失败！");
		system("pause");
		return 0;
	}
	
/* Modbus 通信 */
	printf("\n\n---Modbus 通信开始---");
	/* 发送modbus包 */
	modbus_header *m_h = (modbus_header *)malloc(sizeof(modbus_header));
	m_h->work_pro = htons(0x0000);
	m_h->proto = htons(0x0000);
	m_h->len = htons(0x0005);
	m_h->unit = 0x00;
	m_h->fun_code = 0x2b;
	m_h->data[0] = 0x0e;
	m_h->data[2] = 0x00;
	int ch[2];
	ch[0] = 3;
	ch[1] = 4;
	for (m_h->data[1] = 0x01; m_h->data[1] <= 0x02; m_h->data[1]++)
	{
		for (i = 0; i < ch[m_h->data[1]-1]; i++)
		{
			t_h->th_len_resv_code = htons(0x5018);
			size_data = 11;
			memcpy(data, m_h, size_data);

			if (send_pack(fp, e_h, i_h, t_h, data, size_data, next_seq, ack) == 1)
				printf("\n   modbus-%.2x%.2x 包发送成功!", m_h->data[1], m_h->data[2]);
			else
			{
				printf("\n   modbus-%.2x%.2x 包发送失败！", m_h->data[1], m_h->data[2]);
				system("pause");
				return 0;
			}

			/* 捕获Modbus-0100包 */
			if ((buffer = get_packet(fp, i_h, t_h, next_seq, ack, 0x0018)) != NULL)
			{
				printf("\n   成功捕获modbus-%.2x%.2x数据包！\n   ", m_h->data[1], m_h->data[2]);
				ih = (ip_header *)(buffer + ETHER_LEN);
				for (int i = 68; i < ntohs(ih->tlen) + ETHER_LEN; i++)
				{
					printf("%c", buffer[i]);
				}
			}
			else
			{
				printf("\n   捕获modbus-%.2x%.2x数据包失败！", m_h->data[1], m_h->data[2]);
				system("pause");
				return 0;
			}
			m_h->data[2]++;
		}
	}

	

	printf("\n---Modbus 通信结束---");

/* 断开 tcp 连接 */
	/* 发送fin ack */
	printf("\n\n---TCP断开连接---");
	t_h->th_len_resv_code = htons(0x5011);
	size_data = 0;
	if (send_pack(fp,e_h,i_h,t_h,data,size_data,next_seq,ack) == 1)
	{
		printf("\n   fin ack 包发送成功!");
	}
	else
	{
		printf("\n   fin ack 包发送失败!");
		system("pause");
		return 0;
	}
	
	/* 接受ack包 */
	if ((buffer = get_packet(fp,i_h,t_h,next_seq,ack,0x0010)) != NULL)
	{
		printf("\n   ack 包接受成功!");
	}
	else
	{
		printf("\n   未收到ack包!");
		system("pause");
		return 0;
	}

	/* 接受fin ack包 、并发送ack包*/
	if ((buffer = get_packet(fp, i_h, t_h, next_seq, ack, 0x0011)) != NULL)
	{
		printf("\n   fin ack 包接受成功!");
	}
	else
	{
		printf("\n   未收到 fin ack 包!");
		system("pause");
		return 0;
	}
	
	/* 发送 ack 包 */
	t_h->th_len_resv_code = htons(0x5010);
	size_data = 0;
	if (send_pack(fp, e_h, i_h, t_h, data, size_data, next_seq, ack) == 1)
	{
		printf("\n   ack 包发送成功！");
	}
	else
	{
		printf("\n   ack 包发送失败！");
		system("pause");
		return 0;
	}
	printf("\n---TCP连接断开成功---");
	pcap_freealldevs(alldevs);		// 释放设备列表
	system("pause");
	return 0;
}