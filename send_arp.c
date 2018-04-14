#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Please choose an interface using: ./a.out en0");
        exit(1);
    }
    const char* if_name = argv[1];
    const char* target_ip_string = argv[2];
    char pcap_errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(if_name, 96, 0, 0, pcap_errbuf);
    if (pcap_errbuf[0] != '\0') {
        fprintf(stderr, "%s", pcap_errbuf);
    }
    if (!pcap) {
        exit(1);
    }
    // struct ether_header header;
    // header.ether_type = htons(ETH_P_ARP);
    // memset(header.ether_dhost, 0xff, sizeof(header.ether_dhost));

    //关闭接口
    pcap_close(pcap);
}