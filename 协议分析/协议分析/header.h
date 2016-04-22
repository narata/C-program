typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

#define ETHER_ADDR_LEN 6			// ethernet address length
#define BUFFER_MAX_LENGTH 65536		// buffer max length 
#define ETHERTYPE_IP 0x0800			// ip protocol 
#define TCP_PROTOCAL 0x0600			// tcp protocol 
#define true 1
#define false 0



/* 14 ethernet header */
typedef struct ether_header {
	u_char ether_dhost[ETHER_ADDR_LEN]; // destination ethernet address 
	u_char ether_shost[ETHER_ADDR_LEN]; // source ethernet addresss
	u_short ether_type;                 // ethernet type
}ether_header;
#define ETHER_LEN 14

/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* 20 IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
}ip_header;

/* 8 UDP header */
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;
#define PSD_LEN 12

/* 20 tcp header */
typedef struct tcp_header {
	u_short th_sport;         // source port 
	u_short th_dport;         // destination port
	u_int th_seq;             // sequence number 
	u_int th_ack;             // acknowledgement number 
	u_short th_len_resv_code; // datagram length and reserved code 
	u_short th_window;        // window 
	u_short th_sum;           // checksum 
	u_short th_urp;           // urgent pointer 
	u_int option[3];
}tcp_header;

/*  12 pseudo-header*/
typedef struct psd_header
{
	ip_address saddr;	//source address
	ip_address daddr;	//destination address
	u_char plh;			//placeholder , 0
	u_char pro_t;		//protocol type
	u_short len;		//TCP/UDP header length 
}psd_header;

/* 本地网络信息 */
typedef struct _netinfo
{
	/* 本机 */
	u_char mac_addr[ETHER_ADDR_LEN];
	ip_address ip_addr;
	ip_address ip_mask;
	/* 网关 */
	ip_address gate_addr;
	ip_address gate_mask;
	u_char gate_mac[ETHER_ADDR_LEN];
	
}net_info;

/* Modbus header */
typedef struct _modbus
{
	u_short work_pro;
	u_short proto;
	u_short len;
	u_char unit;
	u_char fun_code;
	u_char data[4];
}modbus_header;
#define MH_L 11

int get_arp_mac(ip_address ip_addr, u_char mac[6]);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);