#include "pcap.h"
#include <stdlib.h>

void  main0()

{

	pcap_if_t *alldevs, *d;

	int i = 0;

	char errbuf[PCAP_ERRBUF_SIZE];



	if (pcap_findalldevs(&alldevs, errbuf) == -1)

	{

		fprintf(stderr, "Error inpcap_findalldevs: %s\n", errbuf);

		return;

	}



	for (d = alldevs; d; d = d->next)

	{
		printf("%d. %s", ++i, d->name);

		if (d->description)  printf(" (%s)\n", d->description);

		else  printf(" (Nodescription available)\n");

	}



	if (i == 0)

	{
		printf("\nNo interfaces found! Makesure WinPcap is installed.\n");

		return;

	}



	/*We don't need any more the device list. Free it */

	pcap_freealldevs(alldevs);
	system("pause");
	

}