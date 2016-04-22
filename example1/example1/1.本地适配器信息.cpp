#include <stdio.h>
#include <stdlib.h>

#define HAVE_REMOTE
#include <pcap.h>

int main()
{
	pcap_if_t *alldevs;  //表示适配器列表中的一项
	pcap_if_t *d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* get local devices */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	/* print devices list */
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf("(%s)\n", d->description);
		else
			printf("(No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Winpcap is installed.\n");
		return -1;
	}

	pcap_freealldevs(alldevs);	//释放适配器链表空间
	getchar();

	return 0;
}