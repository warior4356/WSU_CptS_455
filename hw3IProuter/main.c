#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#define BUF_SIZ		65536
#define SEND 0
#define RECV 1
#define S_ARP 2
#define R_ARP 3

void recv_all(char * iName);
void recv_arp(char * iName, unsigned char* result);


struct arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    uint16_t opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};

int16_t ip_checksum(void* vdata,size_t length) {
	char* data=(char*)vdata;
	uint32_t acc=0xffff;
	for (size_t i=0;i+1<length;i+=2) 
	{
		uint16_t word;
		memcpy(&word,data+i,2);
		acc+=ntohs(word);
		if (acc>0xffff) 
		{
			acc-=0xffff;
		}
	}
	if (length&1) 
	{
		uint16_t word=0;
		memcpy(&word,data+length-1,1);
		acc+=ntohs(word);
		if (acc>0xffff) 
		{
			acc-=0xffff;
		}
	}
	return htons(~acc);
}

struct in_addr get_ip_saddr(char *if_name, int sockfd){
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_idx) < 0)
		perror("SIOCGIFADDR");
	return ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr;
}

struct in_addr get_netmask(char *if_name, int sockfd){
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if((ioctl(sockfd, SIOCGIFNETMASK, &if_idx)) == -1)
	perror("ioctl():");
	return ((struct sockaddr_in *)&if_idx.ifr_netmask)->sin_addr;
}

void send_arp(char* address, char* iName, char* destIp, short type, unsigned char* result)
{
	printf("Inside ARP Send\n");
	int sockfd, i, byteSent, tx_length = 0;
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	char sendbuf[BUF_SIZ];
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct in_addr addr;
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct arp_header *arp = (struct arp_header *) (sendbuf + sizeof(struct ether_header));

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");
	printf("Socket created\n");	

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, iName, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		printf("SIOCGIFINDEX failed");
	printf("Index Set\n");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, iName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    printf("SIOCGIFHWADDR");
	printf("Mac Set\n");
	
	char my_ip[16]; 
	unsigned char my_ip_split[4];
	strcpy(my_ip, inet_ntoa(get_ip_saddr(iName, sockfd)));
	sscanf(my_ip, "%hhd.%hhd.%hhd.%hhd", &my_ip_split[0], &my_ip_split[1], &my_ip_split[2], &my_ip_split[3]);
	
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	sk_addr.sll_addr[0] = address[0];
	sk_addr.sll_addr[1] = address[1];
	sk_addr.sll_addr[2] = address[2];
	sk_addr.sll_addr[3] = address[3];
	sk_addr.sll_addr[4] = address[4];
	sk_addr.sll_addr[5] = address[5];
	
	memset(sendbuf, 0, BUF_SIZ);
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = address[0];
	eh->ether_dhost[1] = address[1];
	eh->ether_dhost[2] = address[2];
	eh->ether_dhost[3] = address[3];
	eh->ether_dhost[4] = address[4];
	eh->ether_dhost[5] = address[5];
	eh->ether_type = htons(ETH_P_ARP);
	tx_length += sizeof(struct ether_header);

	arp->hardware_type = htons(1);
	arp->protocol_type = htons(0x0800);
	arp->hardware_len = 6;
	arp->protocol_len = 4;
	arp->opcode = htons(type);
	arp->sender_mac[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	arp->sender_mac[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	arp->sender_mac[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	arp->sender_mac[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	arp->sender_mac[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	arp->sender_mac[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	arp->target_mac[0] = address[0];
	arp->target_mac[1] = address[1];
	arp->target_mac[2] = address[2];
	arp->target_mac[3] = address[3];
	arp->target_mac[4] = address[4];
	arp->target_mac[5] = address[5];
	arp->target_ip[0] = destIp[0];
	arp->target_ip[1] = destIp[1];
	arp->target_ip[2] = destIp[2];
	arp->target_ip[3] = destIp[3];
	arp->sender_ip[0] = my_ip_split[0];
	arp->sender_ip[1] = my_ip_split[1];
	arp->sender_ip[2] = my_ip_split[2];
	arp->sender_ip[3] = my_ip_split[3];
	tx_length += sizeof(struct arp_header);

	byteSent = sendto(sockfd, sendbuf, tx_length, 0,
		(struct sockaddr*)&sk_addr, sk_addr_size);
	printf("byteSent = %d\n", byteSent);
	if(type == 1)
	{
		printf("Listening For Reply!\n");
		recv_arp(iName, result);
	}
}

void recv_arp(char* iName, unsigned char* result)
{
	printf("Inside ARP Recv\n");
	int sockfd, recvLen;
	char buf[BUF_SIZ];
	u_int8_t broadcast[6];
	char* broadcast_addr = "ff:ff:ff:ff:ff:ff";
	sscanf(broadcast_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &broadcast[0], &broadcast[1], &broadcast[2], &broadcast[3], &broadcast[4], &broadcast[5]);
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct ether_header *eh = (struct ether_header *) buf;
	struct arp_header *arp = (struct arp_header *) (buf + sizeof(struct ether_header));

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");
	printf("Socket created\n");	

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, iName, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		printf("SIOCGIFINDEX failed");
	printf("Index Set\n");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, iName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    printf("SIOCGIFHWADDR");
	printf("Mac Set\n");
	while(1)
	{
		int invalid = 1;
		while(invalid)
		{
			invalid = 0;
			memset(&sk_addr, 0, sk_addr_size);
			recvLen = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr, &sk_addr_size);
			printf("recvLen = %d\n", recvLen);
			printf("Broadcast addr = %x:%x:%x:%x:%x:%x\n", broadcast[0], broadcast[1], broadcast[2], 
				broadcast[3], broadcast[4], broadcast[5]);		
			printf("Destination Msg = %x:%x:%x:%x:%x:%x\n", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], 
				eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
			printf("Destination Real = %x:%x:%x:%x:%x:%x\n", ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0], 
				((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1], ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2], 
				((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3], ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4], 
				((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]);
			if((eh->ether_dhost[0] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0] || eh->ether_dhost[1] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1] ||
				eh->ether_dhost[2] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2] || eh->ether_dhost[3] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3] ||
				eh->ether_dhost[4] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4] || eh->ether_dhost[5] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]) &&
				(eh->ether_dhost[0] != broadcast[0] || eh->ether_dhost[1] != broadcast[1] ||
				eh->ether_dhost[2] != broadcast[2] || eh->ether_dhost[3] != broadcast[3] ||
				eh->ether_dhost[4] != broadcast[4] || eh->ether_dhost[5] != broadcast[5]))
			{
				printf("MAC address invalid, ignoring!\n");
				invalid = 1;
			}
		}
		printf("Source = %x:%x:%x:%x:%x:%x\n", eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], 
			eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
		printf("Type = %hi\n", eh->ether_type);
		char my_ip[16]; 
		unsigned char my_ip_split[4];
		strcpy(my_ip, inet_ntoa(get_ip_saddr(iName, sockfd)));
		sscanf(my_ip, "%hhd.%hhd.%hhd.%hhd", &my_ip_split[0], &my_ip_split[1], &my_ip_split[2], &my_ip_split[3]);
		printf("My IP = %s\n", my_ip);
		printf("My IP = %d.%d.%d.%d\n", my_ip_split[0], my_ip_split[1], my_ip_split[2], my_ip_split[3]);
		printf("Target IP = %d.%d.%d.%d\n", arp->target_ip[0], arp->target_ip[1], arp->target_ip[2], arp->target_ip[3]);
		if(arp->opcode == htons((short)1))
		{
			printf("ARP Request Received!\n");
			if(arp->target_ip[0] == my_ip_split[0] && arp->target_ip[1] == my_ip_split[1] && arp->target_ip[2] == my_ip_split[2] && arp->target_ip[3] == my_ip_split[3])
			{
				printf("Sender MAC Address = %x:%x:%x:%x:%x:%x\n", arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2], 
					arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
				printf("Sender IP = %d.%d.%d.%d\n", arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]);
				unsigned char dummy[6];
				send_arp(arp->sender_mac, iName, arp->sender_ip, 2, dummy);
				printf("ARP Reply Sent!\n");
			}
			else
			{
				printf("Not my IP!\n");
			}
		}
		if(arp->opcode == htons((short)2))
		{
			printf("ARP Reply Received!\n");
			if(arp->target_ip[0] == my_ip_split[0] && arp->target_ip[1] == my_ip_split[1] && arp->target_ip[2] == my_ip_split[2] && arp->target_ip[3] == my_ip_split[3])
			{
				printf("Sender MAC Address = %x:%x:%x:%x:%x:%x\n", arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2], 
					arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
				printf("Sender IP = %d.%d.%d.%d\n", arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]);
				for(int i = 0; i < 6; i++)
				{
					result[i] = arp->sender_mac[i];
				}
				return;
			}
			else
			{
				printf("Not my IP!\n");
			}
		}
	}
}

void send_message(char* iName, unsigned char* destIPRaw, unsigned char* routerIP, char* message)
{
	printf("Inside Send\n");
	int sockfd, i, byteSent, tx_length = 0;
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	char sendbuf[BUF_SIZ];
	unsigned char address[6];
	char hw_addr[6];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *ip = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	int sk_addr_size = sizeof(struct sockaddr_ll);
	unsigned char destIP[4];
	sscanf(destIPRaw, "%hhd.%hhd.%hhd.%hhd", &destIP[0], &destIP[1], &destIP[2], &destIP[3]);

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");
	printf("Socket created\n");	

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, iName, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		printf("SIOCGIFINDEX failed");
	printf("Index Set\n");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, iName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    printf("SIOCGIFHWADDR");
	printf("Mac Set\n");

	char my_ip[16], my_netmask[16]; 
	unsigned char my_ip_split[4], my_netmask_split[4], my_subnet_split[4], dest_subnet_split[4];
	strcpy(my_netmask, inet_ntoa(get_netmask(iName, sockfd)));
	printf("My Netmask = %s\n", my_netmask);
	sscanf(my_netmask, "%hhd.%hhd.%hhd.%hhd", &my_netmask_split[0], &my_netmask_split[1], &my_netmask_split[2], &my_netmask_split[3]);
	printf("My Netmask Split = %d.%d.%d.%d\n", my_netmask_split[0], my_netmask_split[1], my_netmask_split[2], my_netmask_split[3]);
	
	strcpy(my_ip, inet_ntoa(get_ip_saddr(iName, sockfd)));
	printf("My IP = %s\n", my_ip);
	sscanf(my_ip, "%hhd.%hhd.%hhd.%hhd", &my_ip_split[0], &my_ip_split[1], &my_ip_split[2], &my_ip_split[3]);
	printf("My IP Split = %d.%d.%d.%d\n", my_ip_split[0], my_ip_split[1], my_ip_split[2], my_ip_split[3]);
	for(int i = 0; i < 4; i++)
	{
		my_subnet_split[i] = my_netmask_split[i]&my_ip_split[i];
	}
	printf("My Subnet Split = %d.%d.%d.%d\n", my_subnet_split[0], my_subnet_split[1], my_subnet_split[2], my_subnet_split[3]);	
	
	printf("Dest IP = %d.%d.%d.%d\n", destIP[0], destIP[1], destIP[2], destIP[3]);
	for(int i = 0; i < 4; i++)
	{
		dest_subnet_split[i] = my_netmask_split[i]&destIP[i];
	}
	printf("Dest Subnet Split = %d.%d.%d.%d\n", dest_subnet_split[0], dest_subnet_split[1], dest_subnet_split[2], dest_subnet_split[3]);
	

	printf("Router IP = %d.%d.%d.%d\n", routerIP[0], routerIP[1], routerIP[2], routerIP[3]);
	
	char* broadcast_addr = "ff:ff:ff:ff:ff:ff";
	sscanf(broadcast_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
	if(dest_subnet_split[0] == my_subnet_split[0] && dest_subnet_split[1] == my_subnet_split[1] && dest_subnet_split[2] == my_subnet_split[2] && dest_subnet_split[3] == my_subnet_split[3])
	{
		send_arp(hw_addr, iName, destIP, 1, address);
		printf("Dest MAC Address = %x:%x:%x:%x:%x:%x\n", address[0], address[1], address[2], 
						address[3], address[4], address[5]);
	}
	else
	{
		send_arp(hw_addr, iName, routerIP, 1, address);
		printf("Router MAC Address = %x:%x:%x:%x:%x:%x\n", address[0], address[1], address[2], 
						address[3], address[4], address[5]);
		//sscanf("6a:bc:e2:c3:25:59", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &address[0], &address[1], &address[2], &address[3], &address[4], &address[5]);
	}
	
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	sk_addr.sll_addr[0] = address[0];
	sk_addr.sll_addr[1] = address[1];
	sk_addr.sll_addr[2] = address[2];
	sk_addr.sll_addr[3] = address[3];
	sk_addr.sll_addr[4] = address[4];
	sk_addr.sll_addr[5] = address[5];

	memset(sendbuf, 0, BUF_SIZ);
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = address[0];
	eh->ether_dhost[1] = address[1];
	eh->ether_dhost[2] = address[2];
	eh->ether_dhost[3] = address[3];
	eh->ether_dhost[4] = address[4];
	eh->ether_dhost[5] = address[5];
	eh->ether_type = htons(ETH_P_IP);
	tx_length += sizeof(struct ether_header);
	
	ip->saddr = get_ip_saddr(iName, sockfd).s_addr;
	ip->daddr = inet_addr(destIPRaw);
	ip->version = 4;
	ip->ihl = 5;
	ip->check = 0;
	ip->tot_len = htons(sizeof(struct iphdr) + strlen(message));
	ip->ttl = 0xFF;
	ip->protocol = IPPROTO_TCP;
	tx_length += sizeof(struct iphdr);
	
	for(i = 0; i < strlen(message); i++)
	{
		sendbuf[tx_length+i] = message[i];
	}
	tx_length += i;
	
	ip->check = ip_checksum(ip, 20);
	byteSent = sendto(sockfd, sendbuf, tx_length, 0,
		(struct sockaddr*)&sk_addr, sk_addr_size);
	printf("byteSent = %d\n", byteSent);
	printf("message = %s\n", message);

}

void recv_message(char * iName)
{
	printf("Inside Recv\n");
	int sockfd, recvLen;
	char buf[BUF_SIZ];
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct ether_header *eh = (struct ether_header *) buf;

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");
	printf("Socket created\n");	

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, iName, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		printf("SIOCGIFINDEX failed");
	printf("Index Set\n");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, iName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    printf("SIOCGIFHWADDR");
	printf("Mac Set\n");

	memset(&sk_addr, 0, sk_addr_size);
	recvLen = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr, &sk_addr_size);
	printf("recvLen = %d\n", recvLen);
	printf("Destination Msg = %x:%x:%x:%x:%x:%x\n", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], 
		eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
	printf("Destination Real = %x:%x:%x:%x:%x:%x\n", ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0], 
		((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1], ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2], 
		((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3], ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4], 
		((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]);
	if(eh->ether_dhost[0] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0] || eh->ether_dhost[1] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1] ||
		eh->ether_dhost[2] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2] || eh->ether_dhost[3] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3] ||
		eh->ether_dhost[4] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4] || eh->ether_dhost[5] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5])
	{
		printf("MAC adresses do not match, ignoring!\n");
		return;
	}
	printf("Source = %x:%x:%x:%x:%x:%x\n", eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], 
		eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
	printf("Type = %hi\n", eh->ether_type);
	printf("Payload = ");
	for(int i = sizeof(struct ether_header); i < recvLen; i++)
	{
		printf("%c", buf[i]);
	}
	printf("\n");

}

void recv_all(char * iName)
{
	printf("Inside Recv\n");
	int sockfd, recvLen;
	char buf[BUF_SIZ];
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct ether_header *eh = (struct ether_header *) buf;

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");
	printf("Socket created\n");	

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, iName, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		printf("SIOCGIFINDEX failed");
	printf("Index Set\n");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, iName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    printf("SIOCGIFHWADDR");
	printf("Mac Set\n");

	while(1)
	{
		memset(&sk_addr, 0, sk_addr_size);
		recvLen = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr, &sk_addr_size);
		printf("\nMessage Received!\nrecvLen = %d\n", recvLen);
		printf("ether_type = %x\n", htons(eh->ether_type));
		
		if(eh->ether_type == htons(ETH_P_ARP))
		{
			struct arp_header *arp = (struct arp_header *) (buf + sizeof(struct ether_header));
			u_int8_t broadcast[6];
			char* broadcast_addr = "ff:ff:ff:ff:ff:ff";
			sscanf(broadcast_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &broadcast[0], &broadcast[1], &broadcast[2], &broadcast[3], &broadcast[4], &broadcast[5]);
			
			printf("ARP Received!\n");
			printf("Broadcast addr = %x:%x:%x:%x:%x:%x\n", broadcast[0], broadcast[1], broadcast[2], 
				broadcast[3], broadcast[4], broadcast[5]);		
			printf("Destination Msg = %x:%x:%x:%x:%x:%x\n", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], 
				eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
			printf("Destination Real = %x:%x:%x:%x:%x:%x\n", ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0], 
				((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1], ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2], 
				((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3], ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4], 
				((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]);
			if((eh->ether_dhost[0] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0] || eh->ether_dhost[1] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1] ||
				eh->ether_dhost[2] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2] || eh->ether_dhost[3] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3] ||
				eh->ether_dhost[4] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4] || eh->ether_dhost[5] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]) &&
				(eh->ether_dhost[0] != broadcast[0] || eh->ether_dhost[1] != broadcast[1] ||
				eh->ether_dhost[2] != broadcast[2] || eh->ether_dhost[3] != broadcast[3] ||
				eh->ether_dhost[4] != broadcast[4] || eh->ether_dhost[5] != broadcast[5]))
			{
				printf("MAC address invalid, ignoring!\n");
				continue;
			}
			printf("Source = %x:%x:%x:%x:%x:%x\n", eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], 
				eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
			printf("Type = %hi\n", eh->ether_type);
			char my_ip[16]; 
			unsigned char my_ip_split[4];
			strcpy(my_ip, inet_ntoa(get_ip_saddr(iName, sockfd)));
			sscanf(my_ip, "%hhd.%hhd.%hhd.%hhd", &my_ip_split[0], &my_ip_split[1], &my_ip_split[2], &my_ip_split[3]);
			//printf("My IP = %s\n", my_ip);
			printf("My IP = %d.%d.%d.%d\n", my_ip_split[0], my_ip_split[1], my_ip_split[2], my_ip_split[3]);
			printf("Target IP = %d.%d.%d.%d\n", arp->target_ip[0], arp->target_ip[1], arp->target_ip[2], arp->target_ip[3]);
			if(arp->opcode == htons((short)1))
			{
				printf("ARP Request Received!\n");
				if(arp->target_ip[0] == my_ip_split[0] && arp->target_ip[1] == my_ip_split[1] && arp->target_ip[2] == my_ip_split[2] && arp->target_ip[3] == my_ip_split[3])
				{
					printf("Sender MAC Address = %x:%x:%x:%x:%x:%x\n", arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2], 
						arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
					printf("Sender IP = %d.%d.%d.%d\n", arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]);
					unsigned char dummy[6];
					send_arp(arp->sender_mac, iName, arp->sender_ip, 2, dummy);
					printf("ARP Reply Sent!\n");
				}
				else
				{
					printf("Not my IP!\n");
				}
			}
			if(arp->opcode == htons((short)2))
			{
				printf("ARP Reply Received!\n");
				if(arp->target_ip[0] == my_ip_split[0] && arp->target_ip[1] == my_ip_split[1] && arp->target_ip[2] == my_ip_split[2] && arp->target_ip[3] == my_ip_split[3])
				{
					printf("Sender MAC Address = %x:%x:%x:%x:%x:%x\n", arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2], 
						arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
					printf("Sender IP = %d.%d.%d.%d\n", arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]);
				}
				else
				{
					printf("Not my IP!\n");
				}
			}
		}
		
		else if(eh->ether_type == htons(ETH_P_IP))
		{
			printf("IP Received!\n");
			printf("Destination Msg = %x:%x:%x:%x:%x:%x\n", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], 
				eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
			printf("Destination Real = %x:%x:%x:%x:%x:%x\n", ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0], 
				((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1], ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2], 
				((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3], ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4], 
				((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]);
			if(eh->ether_dhost[0] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0] || eh->ether_dhost[1] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1] ||
				eh->ether_dhost[2] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2] || eh->ether_dhost[3] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3] ||
				eh->ether_dhost[4] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4] || eh->ether_dhost[5] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5])
			{
				printf("MAC adresses do not match, ignoring!\n");
			}
			printf("Source = %x:%x:%x:%x:%x:%x\n", eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], 
				eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
			printf("Type = %hi\n", eh->ether_type);
			printf("Payload = ");
			for(int i = sizeof(struct ether_header) + sizeof(struct iphdr); i < recvLen; i++)
			{
				printf("%c", buf[i]);
			}
			printf("\n");
		}
	}
}

int main(int argc, char *argv[])
{
	int mode;
	char hw_addr[6];
	unsigned char dest_ip[16];
	unsigned char router_ip[4];
	char interfaceName[IFNAMSIZ];
	char buf[BUF_SIZ];
	memset(buf, 0, BUF_SIZ);
	unsigned char dummy[6];
	
	int correct=0;
	if (argc > 1){
		if(strncmp(argv[1],"Send", 4)==0)
		{
			if (argc == 6)
			{
				mode=SEND; 
				//sscanf(argv[3], "%hhd.%hhd.%hhd.%hhd", &dest_ip[0], &dest_ip[1], &dest_ip[2], &dest_ip[3]);
				strcpy(dest_ip, argv[3]);
				sscanf(argv[4], "%hhd.%hhd.%hhd.%hhd", &router_ip[0], &router_ip[1], &router_ip[2], &router_ip[3]);
				strncpy(buf, argv[5], BUF_SIZ);
				correct=1;
				printf("  buf: %s\n", buf);
			}
		}
		else if(strncmp(argv[1],"Recv", 4)==0)
		{
			if (argc == 3)
			{
				mode=RECV;
				correct=1;
			}
		}
		else if(strncmp(argv[1],"S_ARP", 5)==0)
		{
			if (argc == 4)
			{
				mode = S_ARP;
				char* broadcast_addr = "ff:ff:ff:ff:ff:ff";
				sscanf(broadcast_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
				sscanf(argv[3], "%hhd.%hhd.%hhd.%hhd", &dest_ip[0], &dest_ip[1], &dest_ip[2], &dest_ip[3]);
				correct=1;
			}
		}
		else if(strncmp(argv[1],"R_ARP", 5)==0)
		{
			if (argc == 3)
			{
				mode = R_ARP;
				correct=1;
			}
		}
	 }
	if(!correct)
	{
		fprintf(stderr, "./455_proj2 Send <InterfaceName> <DestIP> <RouterIP> <Message>\n");
		fprintf(stderr, "./455_proj2 Recv <InterfaceName>\n");
		fprintf(stderr, "./455_proj2 S_ARP <InterfaceName> <DestIP>\n");
		//fprintf(stderr, "./455_proj2 R_ARP <InterfaceName>\n");
		exit(1);
	}

	strncpy(interfaceName, argv[2], IFNAMSIZ);

	if(mode == SEND)
	{
		send_message(interfaceName, dest_ip, router_ip, buf);
	}
	else if (mode == RECV)
	{
		recv_all(interfaceName);
	}
	else if (mode == S_ARP)
	{
		send_arp(hw_addr, interfaceName, dest_ip, 1, dummy);
	}
	else if (mode == R_ARP)
	{
		recv_arp(interfaceName, dummy);
	}
	return 0;
}

