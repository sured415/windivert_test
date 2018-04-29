#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdint>
#include "windivert.h"

void dump(u_char *p, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		printf("%02x ", p[i]);
	}
	printf("\n");
}

int main() {
	u_char packet[255];
	WINDIVERT_ADDRESS addr;
	uint32_t packet_len;

	HANDLE handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);

	while (true) {
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len)) {
			printf("warning: failed to read packet \n");
			continue;
		}
		
		PWINDIVERT_IPHDR IP = (PWINDIVERT_IPHDR)packet;

		if (IP->Protocol == 06) {
			u_char* packet_p = &packet[0];
			packet_p += sizeof(WINDIVERT_IPHDR);
			PWINDIVERT_TCPHDR TCP = (PWINDIVERT_TCPHDR)packet_p;

			if ((ntohs(TCP->SrcPort) == 80) || (ntohs(TCP->DstPort) == 80)) {
				printf("************* TCP Port 80 block **************\n");
//				printf("SrcPort = %04x \t DstPort = %04x \n\n", ntohs(TCP->SrcPort), ntohs(TCP->DstPort));
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