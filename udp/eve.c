// Sniffer
// based on https://www.tcpdump.org/pcap.html
// and https://www.winpcap.org/pipermail/winpcap-users/2007-September/002104.html
//
// usage: sudo ./eve
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "packet-headers.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define NETIF "enp0s8"
#define PORT 8080

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_udp *udp; /* The UDP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_payload;

	//for(int i = 0; i < header->len; i++) {
	//	printf("%02x", packet[i]);
	//}
	//printf("\n");

	printf("Jacked a packet with length of [%d]\n", header->len);

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* define/compute udp header offset */
	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + SIZE_UDP);
	
	printf("   Src port: %d\n", ntohs(udp->uh_sport));
	printf("   Dst port: %d\n", ntohs(udp->uh_dport));

	/* define/compute udp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);

	/* compute udp payload (segment) size */
	size_payload = ntohs(udp->uh_ulen);
	
	/* make writable copy of payload */
	char *copy = malloc(size_payload);
	if (copy == NULL) {
		printf("Couldn't allocate memory to hold payload received!");
		return;
	}
	
	memcpy(copy, payload, size_payload - 1);

	copy[size_payload - 1] = '\0'; // ensure 0-terminated string
	
	printf("Got message: %s\n", copy);
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program filter;
	char filter_exp[] = "udp port " STR(PORT);
	bpf_u_int32 mask;
	bpf_u_int32 net;
	const u_char *packet;

	/* Find the properties for the device */
	if (pcap_lookupnet(NETIF, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", NETIF);
		net = 0;
		mask = 0;
	}
	
	/* Open the session in promiscuous mode */
	printf("Opening network interface %s ...\n", NETIF);
	handle = pcap_open_live(NETIF, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", NETIF, errbuf);
		return 2;
	}

	/* Check that device provides Ethernet headers */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", NETIF);
		return 2;
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &filter, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}
	if (pcap_setfilter(handle, &filter) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}

	/* Divert control to pcap */
	printf("Listening to packets ...\n");
	pcap_loop(handle, 0 /*infinite*/, got_packet, (u_char*) NULL);

	/* On error/end: close the session */
	printf("Terminating ...\n");
	pcap_close(handle);

	return 0;
}