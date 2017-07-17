#include <iostream>
#include <stdio.h>
#include <winsock2.h>

#define HAVE_REMOTE
#include "pcap.h"

#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )

using namespace std;

/* 
	Target
	eth : smac, dmac
	ip : sip, dip
	tcp : sport, dport
	data 
*/

typedef struct {
	unsigned char ether_dmac[6];
	unsigned char ether_smac[6];
	unsigned short ether_type;
}ether_header;

typedef struct {
	// 20byte
	unsigned char ip_ver_IHL;
	unsigned char ip_TOS;
	unsigned short ip_length;
	unsigned short ip_packetID;
	unsigned short ip_flag;
	unsigned char ip_TTL;
	unsigned char ip_protocol;
	unsigned short ip_checksum;

	struct in_addr ip_sip;
	struct in_addr ip_dip;

}ip_header;

typedef struct {
	unsigned short tcp_sport;
	unsigned short tcp_dport;
	unsigned int tcp_sqnum;
	unsigned int tcp_acknum;
	unsigned char tcp_offRes;
}tcp_header;


// ---------------- FUNCTIONS ------------------

void print_eth(const unsigned char *data) {
	ether_header *eth;
	eth = (ether_header *) data;

	printf("\n--------------- MAC ADDRESS ----------------\n");
	printf("Destination MAC Address : [%02x:%02x:%02x:%02x:%02x:%02x]\n"
	, eth->ether_dmac[0], eth->ether_dmac[1], eth->ether_dmac[2], 
		eth->ether_dmac[3], eth->ether_dmac[4], eth->ether_dmac[5]);
	
	printf("Source MAC Address : [%02x:%02x:%02x:%02x:%02x:%02x]"
		, eth->ether_smac[0], eth->ether_smac[1], eth->ether_smac[2],
		eth->ether_smac[3], eth->ether_smac[4], eth->ether_smac[5]);
}

int print_ip(const unsigned char *data) {
	ip_header *iph;
	int mask_size = 0;
	iph = (ip_header *)data;

	// IP Header to SIP -> 12byte
	printf("\n--------------- IPv4 ADDRESS ---------------\n");
	printf("Destination IP Address : %s\n", inet_ntoa(iph->ip_dip));
	printf("Source IP Address : %s", inet_ntoa(iph->ip_sip));

	// get pure mask size from bit mask operations
	mask_size = (iph->ip_ver_IHL) & 15;
	return mask_size * 4;
}

int print_tcp(const unsigned char *data) {
	tcp_header *tcph;
	tcph = (tcp_header *)data;

	// get pure offset from bit mask oprations
	int pure_offset = 0;
	pure_offset = tcph->tcp_offRes & 15;
	pure_offset = pure_offset >> 4;
	pure_offset = pure_offset & 240;

	printf("\n----------------- TCP PORT -----------------\n");
	printf("Destination PORT : %d\n", ntohs(tcph->tcp_dport));
	printf("Source PORT : %d\n", ntohs(tcph->tcp_sport));

	return pure_offset * 4;
}

void print_data(const unsigned char *data) {
	// print 40byte of data
	printf("------------------- DATA -------------------\n");
	printf("[ %02x %02x %02x %02x %02x | %02x %02x %02x %02x %02x ]\n",
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9]);
	printf("[ %02x %02x %02x %02x %02x | %02x %02x %02x %02x %02x ]\n",
		data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19]);
	printf("[ %02x %02x %02x %02x %02x | %02x %02x %02x %02x %02x ]\n",
		data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27], data[28], data[29]);
	printf("[ %02x %02x %02x %02x %02x | %02x %02x %02x %02x %02x ]\n",
		data[30], data[31], data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39]);
}

int main(){

	// example : Opening an adapter and capturing the packets

	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int count = 0;
	int i = 0;
	int offset = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next){
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d): ", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i){
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
	)) == NULL)	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	pcap_freealldevs(alldevs);

	// set required variables
	int ip_res = 0, tcp_res = 0;
	int res;
	int sum_header = 0;

	struct pcap_pkthdr *header;
	
	const unsigned char *pkt_data; // byte pointer

	// get next packet from pcap_next_ex functions 
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;
		if (count>10) break;
		
		cout << "##################################################\n";
		cout << "#################### " << "Packet " << count+1 << " #################### " << endl;
		print_eth(pkt_data);
		for (int i = 0; i < 14; i++)	pkt_data++;

		
		
		ip_res = print_ip(pkt_data);
		// move header pointer by "for" loop
		for (int i = 0; i < ip_res; i++)	pkt_data++;

		// SIP + 8byte -> Payload
		tcp_res = print_tcp(pkt_data);

		sum_header = 14 + ip_res + tcp_res;
		
		// move header pointer by "for" loop
		for (int i = 0; i < tcp_res; i++)	pkt_data++;

		print_data(pkt_data);

		cout << endl;
		count++;	// counting printed packets
	}
}