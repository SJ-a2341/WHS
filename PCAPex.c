#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

/* Ethernet header */
struct ethheader {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

/* IP Header */
struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

/* MAC 주소를 문자열로 변환하는 함수 */
void mac_to_str(const u_char *mac, char *mac_str) {
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* 패킷을 분석하고 출력하는 함수 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800) {
        return; // IPv4가 아니면 무시
    }

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    if (ip->iph_protocol != 6) { // TCP가 아니면 무시
        return;
    }

    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

    char src_mac[18], dst_mac[18]; 
    mac_to_str(eth->ether_shost, src_mac);
    mac_to_str(eth->ether_dhost, dst_mac);

    printf("Ethernet Header: %s / %s\n", src_mac, dst_mac);
    printf("IP Header: %s / %s\n", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));
    printf("TCP Header: %d / %d\n\n", ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // TCP 패킷만 캡처
    bpf_u_int32 net, mask;

    if (pcap_lookupnet("ens33", &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);


    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
