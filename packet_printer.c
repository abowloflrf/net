//
// Created by ruofeng on 18-4-15.
//

#include "packet_printer.h"

void printer(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet)
{
    fprintf(stdout, "User args:%s\n", args);
    struct ether_header *eptr;

    if (packet == NULL) {
        fprintf(stdout, "Didn't grab packet\n");
        exit(1);
    }

    /*  struct pcap_pkthdr {
        struct timeval ts;   time stamp
        bpf_u_int32 caplen;  length of portion present
        bpf_u_int32;         lebgth this packet (off wire)
        }
     */

    fprintf(stdout, "Grabbed packet of length %d\n", hdr->len);
    fprintf(stdout, "Recieved at ..... %s", ctime((const time_t *) &hdr->ts.tv_sec));
    fprintf(stdout, "Ethernet address length is %d\n", ETHER_HDR_LEN);

    //获取以太帧头部信息
    eptr = (struct ether_header *) packet;
    ethhdr_printer(eptr);

    //检查数据包类型，这里只解析两种：arp与ip数据包，其他类型直接丢弃并退出
    if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {
        fprintf(stdout,
                "Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));
    }
    else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP) {
        fprintf(stdout,
                "Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));
        struct ether_arp *arp = (struct ether_arp *) (packet + 14);//获取arp包内容
        arp_printer(arp);
    }
    else {
        fprintf(stdout, "Ethernet type %x not IP or ARP", ntohs(eptr->ether_type));
        exit(1);
    }
    fprintf(stdout, "\n");
}

void ethhdr_printer(struct ether_header *eptr)
{
    u_char *ptr;
    int i;

    //输出目的地址
    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN;
    fprintf(stdout, " Destination Address:  ");
    do {
        fprintf(stdout, "%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
    }
    while (--i > 0);
    fprintf(stdout, "\n");

    //输出源地址
    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN;
    fprintf(stdout, " Source Address:  ");
    do {
        fprintf(stdout, "%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
    }
    while (--i > 0);
    fprintf(stdout, "\n");
};

void arp_printer(struct ether_arp *arp)
{
    //获取arp请求类型，请求还是应答
    switch (ntohs(arp->ea_hdr.ar_op)) {
    case ARPOP_REQUEST:printf("ARP type: request\n");
        break;
    case ARPOP_REPLY:printf("ARP type: reply\n");
        break;
    default:fprintf(stdout, "ARP type: other\n");
    }

    char srcip_str[16];
    char tarip_str[16];
    //组合输出Target IP与Sender IP
    snprintf(srcip_str, 16, "%d.%d.%d.%d", arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], arp->arp_spa[3]);
    snprintf(tarip_str, 16, "%d.%d.%d.%d", arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], arp->arp_tpa[3]);
    fprintf(stdout, " Sender IP: %s\n Target IP: %s\n", srcip_str, tarip_str);
};