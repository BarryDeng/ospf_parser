#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcap/bpf.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <string.h>

#define MAX_IP_LEN 15
#define MAX_INTERFACE_LEN 15

extern char *optarg;
extern int opterr;

char ip[MAX_IP_LEN] = "127.0.0.1";
int port = 8000;
char interface[MAX_INTERFACE_LEN] = "test1";

void handlePacket(unsigned char *,const struct pcap_pkthdr *, const unsigned char *);
void handleEthHdr(struct ether_header *);
void handleIpHdr(struct ip *);

FILE* output_stream;
char* output_buf;
int invalid;
size_t buf_size = 0;

extern void handleOSPF(const u_char *, u_int);
extern void initsock(const char *, int);
extern void writeToServer(const char *);

void handlePacket(unsigned char *argument,const struct pcap_pkthdr *packet_header,const unsigned char *buffer) 
{
    output_stream = open_memstream(&output_buf, &buf_size);
    invalid = 0;

	// fprintf(output_stream, "%s\n", ctime((time_t *)&(packet_header->ts.tv_sec))); //标准时间格式
	fprintf(output_stream, "%ld.%06ld; ", packet_header->ts.tv_sec, packet_header->ts.tv_usec);
	fprintf(output_stream, "%s; ", interface);  

	struct ether_header * eth = (struct ether_header *)buffer;
	handleEthHdr(eth);

	void * netHdr = (void*)eth + sizeof(struct ether_header);
	if (ntohs(eth->ether_type) == ETH_P_IP)
	{
		struct ip * ip = (struct ip *)(buffer + sizeof(struct ether_header));
		handleIpHdr(ip);
		void * transHdr = (void*)ip + sizeof(struct iphdr);

		switch (ip->ip_p) 
		{
			default:
				break;
		}

	}
	// dumpIntoFile(file, buffer, size);

	fprintf(output_stream, "\n");
    fclose(output_stream);
    if (invalid) {
        memset(output_buf, 0, buf_size);
    }
    // fprintf(server_sock, "%s", output_buf);
    writeToServer(output_buf);
    free(output_buf);
}

void handleEthHdr(struct ether_header * eth)
{
	fprintf(output_stream, "%s %s; ", strdup(ether_ntoa((const struct ether_addr *)&eth->ether_shost)), strdup(ether_ntoa((const struct ether_addr *)&eth->ether_dhost))); 
	switch(ntohs(eth->ether_type))
	{
		case ETH_P_IP:
			fprintf(output_stream, "[IP] ");
			break;
		case ETH_P_ARP:
			fprintf(output_stream, "[ARP] ");
			break;
		default:
			fprintf(output_stream, "[OTHER] ");
			break;
	}
}

void handleIpHdr(struct ip * ip)
{
	// printf("\033[32m");
	// printf("%s => %s\t", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
	// printHostName(ip->ip_src);
	fprintf(output_stream, "(%s)", inet_ntoa(ip->ip_src));
	fprintf(output_stream, " => ");
	fprintf(output_stream, "(%s)", inet_ntoa(ip->ip_dst));
	// printf(" \033[0m");

	fprintf(output_stream, "(tos %x, ttl %d, id %d, offset %d, flags ",
			ip->ip_tos, ip->ip_ttl, ntohs(ip->ip_id), ntohs(ip->ip_off) & IP_OFFMASK);
	if (ntohs(ip->ip_off) & IP_RF)
	{
		fprintf(output_stream, "[RF]");
	}
	else if (ntohs(ip->ip_off) & IP_DF)
	{
		fprintf(output_stream, "[DF]");
	}
	else if (ntohs(ip->ip_off) & IP_MF)
	{
		fprintf(output_stream, "[MF]");
	}
	fprintf(output_stream, ", proto %d, length %d); ", ip->ip_p, ntohs(ip->ip_len));

	switch (ip->ip_p)
	{
		case IPPROTO_TCP:
			fprintf(output_stream, "[TCP]; ");
			break;
		case IPPROTO_UDP:
			fprintf(output_stream, "[UDP]; ");
			break;
		case IPPROTO_ICMP:
			fprintf(output_stream, "[ICMP]; ");
			break;
		case 89: // IPPROTO_OSPF
			fprintf(output_stream, "[OSPF]; ");
			handleOSPF((const u_char *)ip + 4 * ip->ip_hl, ntohs(ip->ip_len) - 4 * ip->ip_hl);
			break;
		default:
			fprintf(output_stream, "[OTHER]; ");
			break;
	}

}

int main(int argc, char *argv[])
{
	int c;
	while ((c = getopt(argc, argv, "h:p:i:")) != -1)
	{
		switch (c)
		{
			case 'h':
				strncpy(ip, optarg, MAX_IP_LEN);
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'i':
				strncpy(interface, optarg, MAX_INTERFACE_LEN);
				break;
			default:
				break;
		}
	}

	initsock(ip, port);

	char error_content[PCAP_ERRBUF_SIZE] = { 0 };

	bpf_u_int32 netp = 0, maskp = 0;  
	pcap_t * device = NULL;  
	int ret = 0;  

	ret = pcap_lookupnet(interface, &netp, &maskp, error_content);  
	if(ret == -1)  
	{  
		puts(error_content);  
		exit(-1);  
	}  	

	struct in_addr tmp;
	tmp.s_addr = netp;
	printf("Address: %s\n", inet_ntoa(tmp));

	device = pcap_open_live(interface, 1024, 1, 0, error_content);  
	if(NULL == device)  
	{  
		puts(error_content);  
		exit(-1);  
	}  

	struct bpf_program filter;  
	pcap_compile(device, &filter, "proto ospf", 1, 0);  
	pcap_setfilter(device, &filter);  

	if( pcap_loop(device, -1, handlePacket, NULL) < 0 )  
	{  
		perror("pcap_loop");  
	}  

	pcap_close(device); 
	
	return 0;	
}
