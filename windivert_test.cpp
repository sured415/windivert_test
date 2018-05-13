#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "windivert.h"
#include "win32\libnet.h"

#define MAXBUF  0xFFFF

int main() {
	u_char packet[MAXBUF];
	WINDIVERT_ADDRESS addr;
	uint32_t packet_len;

	HANDLE handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);

	while (true) {
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len)) {
			printf("warning: failed to read packet \n");
			continue;
		}
		
		struct libnet_ipv4_hdr* ipH = (struct libnet_ipv4_hdr *)packet;

		if (ipH->ip_p == 6) {
			u_char* packet_p = &packet[0];
			packet_p += (ipH->ip_hl * 4);
			struct libnet_tcp_hdr* tcpH = (struct libnet_tcp_hdr *)packet_p;

			if ((ntohs(tcpH->th_sport) == 80) || (ntohs(tcpH->th_dport) == 80)) {
				printf("************* TCP Port 80 block **************\n");
				continue;
			}
		}
		if (!WinDivertSend(handle, packet, packet_len, &addr, NULL)) {
			printf("******* warning: failed to send packet *******\n");
		}
		else printf("****************** success *******************\n");
	}
	return 0;
}