#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <sys/user.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/un.h>
#include <sys/eventfd.h>
#include "sys/types.h"

unsigned char BROADCAST_ADDR[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
unsigned char STATION_ADDR[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

struct eth_header {
	unsigned char destaddr[6];
	unsigned char srcaddr[6];
	unsigned short etherType;
};

struct myarp_header {
	unsigned int len;
	unsigned char ethAddr[6];
	unsigned char data[0];
};

struct registered_dst {
	char* id;				// virtual machine identifier
	unsigned char dst[6];	// the vm MAC address 
	struct registered_dst* next;
};

int sock_ll;
char* interface;
int init_socket(unsigned short ethr_type, int* sock_ll_ptr);
void sendFrame(unsigned char* dst_mac, unsigned short ether_type, unsigned char* data, int len);
void dispatchReceivedFrame(unsigned char* buff_ptr);
void receiveARPFrame(unsigned char* dst_mac, unsigned char* arp_packet);
void receiveDataFrame(unsigned char* dst_mac, unsigned char* data_packet);


unsigned char* name;	// my vm name
struct registered_dst dst_list; // arp cache list

int main(int argc, char* argv[]) {
	char* target;
	unsigned char buffer[1500];
	unsigned int received = 0;

	interface = strdup(argv[1]);	// the interface name on my vm, ex.: "ethx" "enpXsX"
	name = strdup(argv[2]);			// the my vm name, ex.: "VMx" 
	target = strdup(argv[3]);		// the peer vm name, ex.: "VMy"

	dst_list.next = NULL;
	if (init_socket(ETH_P_ALL, &sock_ll) == -1) {
		printf("Socket Error - Terminate Program\n");
		return 0;
	}


	/* !!!! VM2 main code !!!! */
	while (1) {
		received = recv(sock_ll, buffer, 1500, 0);
		dispatchReceivedFrame(buffer);
	}

	close(sock_ll);
	return 0;
}

void dispatchReceivedFrame(unsigned char* ptr) {
	struct eth_header* eh;
	unsigned short receivedEtherType;

	eh = (struct eth_header*)ptr;
	ptr += sizeof(struct eth_header);

	receivedEtherType = htons(eh->etherType);

	switch (receivedEtherType) {
	case 0xFFFE:
		receiveARPFrame(eh->srcaddr, ptr);
		break;
	case 0xFFFD:
		receiveDataFrame(eh->srcaddr, ptr);
		break;
	default:
		break;
	}
}

void receiveARPFrame(unsigned char* dst, unsigned char* arp) {
	struct myarp_header* ra;
	struct myarp_header* mah;
	unsigned char* receivedId;
	unsigned int size = sizeof(struct myarp_header) + strlen(name);
	ra = (struct myarp_header*)arp;

	printf("ARP Received from %x:%x:%x:%x:%x:%x.\n", dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);

	// ! Allocate memory for receivedId. Size is received identifier length + 1. !
	receivedId = malloc(ra->len + 1);
	// ! Get ReceivedID from received packets !
	memcpy(receivedId, ra->data, ra->len);
	// ! When you get the receivedId, ID String must have NULL value at last for proper operation of strcmp. !
	receivedId[sizeof(receivedId) - 1] = NULL;

	if (strcmp(name, receivedId)) {
		printf("Received Target name is not mine. ignore..\n");
		return;
	}

	mah = (struct myarp_header*)malloc(size);
	// ! Make ARP Reply. Fill identifier length, identifier and the ethernet_address field of ARP Reply with its MAC Address(STATION_ADDR). !
	mah->len = strlen(name);
	memcpy(mah->ethAddr, STATION_ADDR, 6);
	memcpy(mah->data , receivedId, mah->len);	

	sendFrame(dst, 0xFFFE, (unsigned char*)mah, size);
}

void receiveDataFrame(unsigned char* dst, unsigned char* data) {
	printf("Received Data : %s\n", data);
	/* !!!! VM2 main code !!!! */
	sendFrame(dst, 0xFFFD, "Nice to meet you!\n", strlen("Nice to meet you!\n"));
}


void sendFrame(unsigned char* dst, unsigned short type, unsigned char* data, int len) {
	unsigned char* msgbuf, * msgbuf_wrptr;
	int msgLength = 0;
	int bytes = 0;
	struct eth_header* eh;

	msgbuf = (unsigned char*)malloc(2000);
	if (msgbuf == NULL) {
		return;
	}

	memset(msgbuf, 0, 2000);
	msgbuf_wrptr = msgbuf;

	eh = (struct eth_header*)msgbuf_wrptr;

	// ! Build ethernet header part of frame and frame payload. !
	memcpy(eh->destaddr, dst, 6);
	memcpy(eh->srcaddr, STATION_ADDR, 6);
	eh->etherType = htons(type);

	msgbuf_wrptr += sizeof(struct eth_header);
	memcpy(msgbuf_wrptr, data, len);
	msgbuf_wrptr += len;

	bytes = send(sock_ll, msgbuf, (int)(msgbuf_wrptr - msgbuf), 0);
	free(msgbuf);
}

int init_socket(unsigned short etype, int* sock) { // Initialize socket for L2.
	struct sockaddr_ll addr;
	struct ifreq if_request;
	int lsock;
	int rc;
	struct packet_mreq multicast_req;

	if (NULL == sock)
		return -1;

	*sock = -1;

	lsock = socket(PF_PACKET, SOCK_RAW, htons(etype));

	if (lsock < 0) {
		printf("Socket Creation Error\n");
		return -1;
	}

	memset(&if_request, 0, sizeof(if_request));

	strncpy(if_request.ifr_name, interface, sizeof(if_request.ifr_name) - 1);


	rc = ioctl(lsock, SIOCGIFHWADDR, &if_request);
	if (rc < 0) {
		printf("IOCTL Error\n");
		close(lsock);
		return -1;
	}

	memcpy(STATION_ADDR, if_request.ifr_hwaddr.sa_data,
		sizeof(STATION_ADDR));

	memset(&if_request, 0, sizeof(if_request));

	strncpy(if_request.ifr_name, interface, sizeof(if_request.ifr_name) - 1);

	rc = ioctl(lsock, SIOCGIFINDEX, &if_request);
	if (rc < 0) {
		printf("IOCTL2 Error\n");
		close(lsock);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = if_request.ifr_ifindex;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(etype);

	rc = bind(lsock, (struct sockaddr*)&addr, sizeof(addr));
	if (0 != rc) {
#if LOG_ERRORS
		fprintf(stderr, "%s - Error on bind %s", __FUNCTION__, strerror(errno));
#endif
		close(lsock);
		return -1;
	}

	rc = setsockopt(lsock, SOL_SOCKET, SO_BINDTODEVICE, interface,
		strlen(interface));
	if (0 != rc) {
		printf("Bind option error\n");
		close(lsock);
		return -1;
	}

	*sock = lsock;

	return 0;
}
