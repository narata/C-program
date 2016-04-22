#define URG 0x20
#define ACK 0x10
#define PSH 0x08
#define RST 0x04
#define SYN 0x02
#define FIN 0x01

/*����IP�ײ�*/
typedef struct _iphdr
{
	unsigned char h_verlen;			//8λ  �汾�ţ�4��+�ײ����ȣ�4��
	unsigned char type;				//8λ  ��������
	unsigned short total_len;		//16λ �ܳ��ȣ��ֽڣ�
	unsigned short ident;			//16λ �����ʶ
	unsigned short frag;			//16λ ��־λ��3��+��ƫ������13��
	unsigned char ttl;				//8λ  ����ʱ�� TTL
	unsigned char protocol;			//8λ  Э�� (TCP, UDP ������)
	unsigned short checksum;		//16λ IP�ײ�У���
	unsigned int source_ip;			//32λ ԴIP��ַ
	unsigned int destination_ip;	//32λ Ŀ��IP��ַ
}IP_HEADER;

/*����TCP�ײ�*/
typedef struct _tcphdr
{
	unsigned short th_sport;		//16λ Դ�˿�
	unsigned short th_dport;		//16λ Ŀ�Ķ˿�
	unsigned int th_seq;			//32λ ���к�
	unsigned int th_ack;			//32λ ȷ�Ϻ�
	unsigned char th_lenres;		//4λ  �ײ�����/6λ������
	unsigned char th_flag;			//6λ  ��־λ
	unsigned short th_win;			//16λ ���ڴ�С
	unsigned short th_sum;			//16λ У���
	unsigned short th_urp;			//16λ ��������ƫ����
}TCP_HEADER;

/*����TCPα�ײ�*/
typedef struct psd_hdr //����TCPα�ײ�
{
	unsigned long saddr;	//Դ��ַ
	unsigned long daddr;	//Ŀ�ĵ�ַ
	char mbz;
	char ptcl;				//Э������
	unsigned short tcpl;	//TCP����
}PSD_HEADER;

/*����ICMP�ײ�*/
typedef struct icmp_hdr
{
	unsigned char  i_type;           // ����
	unsigned char  i_code;           // ����
	unsigned short i_cksum;          // У����
	unsigned short i_id;             // �Ǳ�׼��ICMP�ײ�  
	unsigned short i_seq;
	unsigned long  timestamp;
}ICMP_HEADER;

/*����UDP�ײ�*/
typedef struct udp_hdr
{
	unsigned short uh_sport;
	unsigned short uh_dport;
	unsigned short uh_len;
	unsigned short uh_sum;
}UDP_HEADER;

/*����У���*/
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
