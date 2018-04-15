//
// Created by ruofeng on 18-4-14.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>

int main(int argc, char **argv)
{
    //接受两个参数，接口名称与目的mac地址，后面一个可选参数为伪造的sender ip
    if (argc < 3) {
        printf("Usage: ./Program <interface> <macaddr> [<ipaddr>]\n");
        exit(1);
    }
    //参数1-接口名，从这个接口发出ARP请求
    const char *if_name = argv[1];
    //参数2-ARP请求的IP地址
    const char *target_mac_string = argv[2];
    //若有第三个参数则接受为伪造的sender ip
    if (argc > 3) {
        const char *sender_ip_string = argv[3];
    }

    struct ether_header header;
    header.ether_type = htons(ETH_P_ARP);
    memcpy(header.ether_dhost,(unsigned char)sender_ip_string, sizeof(header.ether_dhost));
}