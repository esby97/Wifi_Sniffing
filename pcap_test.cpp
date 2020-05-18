#include <stdio.h>
#include "ehpacket.h"

#define MAX_PACKET 10000

pcap_header headers[MAX_PACKET];
int pcnt;
int Parsing(FILE* fp);
void ParsingEthernet(FILE* fp);

void ViewPacketHeader(pcap_header * ph);
void ViewEthernet(char* buf);
void ViewIP(char* buf);
void ViewARP(char* buf);
void ViewMac(unsigned char* mac);

unsigned short ntohs(unsigned short value);
char* ntoa(uint addr);

int main()
{
	char fname[256];
	FILE* fp;
	printf("filename : ");
	gets_s(fname, sizeof(fname));
	fopen_s(&fp, fname, "rb");
	if (fp == NULL) {
		printf("[Error]File not opened!\n");
		return 1;
	}
	Parsing(fp);
	fclose(fp);
	return 0;
}

int Parsing(FILE* fp)
{
	pcap_file_header pfh;
	fread(&pfh, sizeof(pfh), 1, fp);
	if (pfh.magic != MAGIC)
	{
		printf("[Error] MAGIC incorrect! \n");
		return -1;
	}
	printf("version : %d.%d\n", pfh.version_major, pfh.version_minor);

	switch (pfh.linktype)
	{
	case 1: ParsingEthernet(fp); break;
	case 6: printf("Not support Token Ring\n"); break;
	case 10: printf("Not support FDDI\n"); break;
	case 0: printf("Not support Loopback\n"); break;
	default: printf("Unknown\n"); break;
	}
	return 0;
}

void ParsingEthernet(FILE* fp)
{
	char *buf = new char[65536];
	pcap_header* ph = headers;
	int i = 0;
	while (feof(fp) == 0)
	{
		if (fread(ph, sizeof(pcap_header), 1, fp) != 1)
		{
			break;
		}

		if (pcnt == MAX_PACKET)
		{
			break;
		}

		ViewPacketHeader(ph);
		fread(buf, 1, ph->len, fp);
		ViewEthernet(buf);
		ph++;	
	}
}

void ViewPacketHeader(pcap_header* ph)
{
	pcnt++;
	printf("\nNo:%d Time:%08d:%06d caplen:%u length:%u \n",
		pcnt, ph->ts.tv_sec, ph->ts.tv_usec, ph->caplen, ph->len);
}

void ViewEthernet(char* buf)
{
	ethernet* ph = (ethernet*)buf;

	printf("=========ETHERNET Header=========\n");
	printf("dst mac:0x");
	ViewMac(ph->dst_mac);

	printf("\tsrc mac:0x");
	ViewMac(ph->src_mac);

	printf("\ttype:%#x\n", ntohs(ph->type));

	switch (ntohs(ph->type))
	{
	case 0x800: ViewIP(buf + sizeof(ethernet)); break;
	case 0x806: ViewARP(buf + sizeof(ethernet)); break;
	default: printf("Not Support Protocol\n"); break;
	}
}

void ViewMac(unsigned char* mac)
{
	int i;
	for (i = 0; i < 5; ++i)
	{
		printf("%02x:", mac[i]);
	}
	printf("%02x", mac[5]);
}

unsigned short ntohs(unsigned short value)
{
	return (value << 8) | (value >> 8);
}

char* ntoa(uint addr)
{
	char* buf = new char[16];
	int idx = 0;
	char* address = (char *)&addr;

	for (int i = 0; i < 3; ++i)
	{
		idx = idx + sprintf(buf+idx, "%d.", (unsigned char)address[i]);
	}
	sprintf(buf + idx, "%d", (unsigned char)address[3]);
	return buf;
}

void ViewIP(char* buf)
{
	iphdr* ip = (iphdr*)buf;
	printf("=============== IPv4 Header ============\n");
	
	printf("src:%s\t", ntoa(ip->src_address));
	printf("dst:%s\n", ntoa(ip->dst_address));

	printf("header length:%d bytes,  ", ip->hlen * 4);
	printf("version:%d,  ", ip->version);
	printf("total length:%d bytes\n", ntohs(ip->tlen));
	printf("id:%d,  ", ntohs(ip->id));
}

void ViewARP(char* buf)
{
	printf("View ARP!\n");
}