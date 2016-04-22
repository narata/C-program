#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>
#include <remote-ext.h>


void main(int argc, char **argv)
{
    pcap_t *indesc,*outdesc;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    FILE *capfile;
    int caplen, sync;
    u_int res;
    pcap_send_queue *squeue;
    struct pcap_pkthdr *pktheader;
    const u_char *pktdata;
    float cpu_time;
    u_int npacks = 0;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0;

	/* ��ȡ���ػ����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s\n  ", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
        
    /* ��ȡ�����ļ����� */
    capfile=fopen(argv[1],"rb");
    if(!capfile){
        printf("Capture file not found!\n");
        return;
    }
    
    fseek(capfile , 0, SEEK_END);
    caplen= ftell(capfile)- sizeof(struct pcap_file_header);
    fclose(capfile);
            
    /* ���ʱ����Ƿ�Ϸ� */
    if(argc == 4 && argv[3][0] == 's')
        sync = TRUE;
    else
        sync = FALSE;

    /* ��ʼ���� */
    /* ����WinPcap�����﷨����һ��Դ�ַ��� */
    if ( pcap_createsrcstr( source,         // Դ�ַ���
                            PCAP_SRC_FILE,  // ����Ҫ�򿪵��ļ�
                            NULL,           // Զ������
                            NULL,           // Զ�������Ķ˿�
                            argv[1],    // ����Ҫ�򿪵��ļ���
                            errbuf          // ���󻺳�
                            ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\n");
        return;
    }
    
    /* �򿪲����ļ� */
    if ( (indesc= pcap_open(source, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the file %s.\n", source);
        return;
    }

    /* ��Ҫ����������� */
    if ( (outdesc= pcap_open(alldevs->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open adapter %s.\n", source);
        return;
    }

    /* ���MAC������ */
    if (pcap_datalink(indesc) != pcap_datalink(outdesc))
    {
        printf("Warning: the datalink of the capture differs from the one of the selected interface.\n");
        printf("Press a key to continue, or CTRL+C to stop.\n");
        getchar();
    }

    /* ���䷢�Ͷ��� */
    squeue = pcap_sendqueue_alloc(caplen);

    /* ���ļ��н����ݰ���䵽���Ͷ��� */
    while ((res = pcap_next_ex( indesc, &pktheader, &pktdata)) == 1)
    {
        if (pcap_sendqueue_queue(squeue, pktheader, pktdata) == -1)
        {
            printf("Warning: packet buffer too small, not all the packets will be sent.\n");
            break;
        }

        npacks++;
    }

    if (res == -1)
    {
        printf("Corrupted input file.\n");
        pcap_sendqueue_destroy(squeue);
        return;
    }

    /* ���Ͷ��� */
    
    cpu_time = (float)clock ();

    if ((res = pcap_sendqueue_transmit(outdesc, squeue, sync)) < squeue->len)
    {
        printf("An error occurred sending the packets: %s. Only %d bytes were sent\n", pcap_geterr(outdesc), res);
    }
    
    cpu_time = (clock() - cpu_time)/CLK_TCK;
    
    printf ("\n\nElapsed time: %5.3f\n", cpu_time);
    printf ("\nTotal packets generated = %d", npacks);
    printf ("\nAverage packets per second = %d", (int)((double)npacks/cpu_time));
    printf ("\n");

    /* �ͷŷ��Ͷ��� */
    pcap_sendqueue_destroy(squeue);

    /* �ر������ļ� */
    pcap_close(indesc);

    /* 
     * �ͷ���������� 
     * IMPORTANT: �ǵ�һ��Ҫ�ر�����������Ȼ�Ͳ��ܱ�֤ 
     * ���е����ݰ����ر����ͳ�ȥ
     */
    pcap_close(outdesc);
	getchar();

    return;
}
