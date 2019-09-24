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

#define BUF_SIZ		65536
#define SEND 0
#define RECV 1

void send_message(char* address, char * iName ,char * message)
{
	printf("Inside Send\n");
	int sockfd, i, byteSent, tx_length = 0;
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	int sk_addr_size = sizeof(struct sockaddr_ll);

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

	for(i = 0; i < strlen(message); i++)
	{
		sendbuf[tx_length+i] = message[i];
	}
	tx_length += i;
	
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	sk_addr.sll_addr[0] = address[0];
	sk_addr.sll_addr[1] = address[1];
	sk_addr.sll_addr[2] = address[2];
	sk_addr.sll_addr[3] = address[3];
	sk_addr.sll_addr[4] = address[4];
	sk_addr.sll_addr[5] = address[5];

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

int main(int argc, char *argv[])
{
	int mode;
	char hw_addr[6];
	char interfaceName[IFNAMSIZ];
	char buf[BUF_SIZ];
	memset(buf, 0, BUF_SIZ);
	
	int correct=0;
	if (argc > 1){
		if(strncmp(argv[1],"Send", 4)==0)
		{
			if (argc == 5)
			{
				mode=SEND; 
				sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
				strncpy(buf, argv[4], BUF_SIZ);
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
		strncpy(interfaceName, argv[2], IFNAMSIZ);
	 }
	if(!correct)
	{
		fprintf(stderr, "./455_proj2 Send <InterfaceName>  <DestHWAddr> <Message>\n");
		fprintf(stderr, "./455_proj2 Recv <InterfaceName>\n");
		exit(1);
	}

	if(mode == SEND)
	{
		send_message(hw_addr, interfaceName, buf);
	}
	else if (mode == RECV)
	{
		recv_message(interfaceName);
	}

	return 0;
}

