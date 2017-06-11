
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

	 /* mock */
    char SHA[] = {0x08, 0x00, 0x27, 0x4b, 0xd6, 0xd3}; // meu mac
    char SPA[] = {0xc0, 0xa8, 0x00, 0x01}; // roteador ip
    char THA[] = {0x08, 0x00, 0x27, 0x4b, 0xd6, 0xd3}; // meu mac
    char TPA[] = {0xc0, 0xa8, 0x00, 0x0b}; // ip lu final 27
    /* mock */


	if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
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

    // for (int i = 0; i < sizeof(buffer); i++) {
    //         printf("%02x ", buffer[i]);
    // }



	/* Envia pacote */
	if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}

	printf("Pacote enviado.\n");

	close(fd);
	return 0;
}
