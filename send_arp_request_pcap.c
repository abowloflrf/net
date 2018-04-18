#include <pcap.h> //libpcap header file

#include <stdio.h> //printf; fprintf
#include <stdlib.h> //memcpy; exit; perror
#include <string.h>

#include <arpa/inet.h>  //htons function; in_addr; inet_aton
#include <net/ethernet.h>  //struct ether_header
#include <net/if.h> //ifreq struct
#include <netinet/ether.h>
#include <netinet/if_ether.h> //struct ether_arp
#include <sys/socket.h> //socket
#include <sys/ioctl.h>

#include "send_arp_request_pcap.h"

void send_arp(char *if_name,char *target_ip_string)
{
    //构造以太帧头部
    struct ether_header header;
    header.ether_type = htons(ETH_P_ARP);
    memset(header.ether_dhost, 0xff, sizeof(header.ether_dhost));

    //构造ARP请求
    struct ether_arp req;
    req.arp_hrd = htons(ARPHRD_ETHER);
    req.arp_pro = htons(ETH_P_IP);
    req.arp_hln = ETHER_ADDR_LEN;
    req.arp_pln = sizeof(in_addr_t);
    req.arp_op = htons(ARPOP_REQUEST);
    memset(&req.arp_tha, 0, sizeof(req.arp_tha));

    //将字符串形式的IP转化为指定结构体，并写入到请求帧结构体中
    struct in_addr target_ip_addr = {0};
    if (!inet_aton(target_ip_string, &target_ip_addr)) {
        fprintf(stderr, "%s is not a valid IP address\n", target_ip_string);
        exit(1);
    }
    memcpy(&req.arp_tpa, &target_ip_addr.s_addr, sizeof(req.arp_tpa));
    //将接口名写入请求帧结构体
    struct ifreq ifr;
    size_t if_name_len = strlen(if_name);
    if (if_name_len < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, if_name, if_name_len);
        ifr.ifr_name[if_name_len] = 0;
    }
    else {
        fprintf(stderr, "Interface name is too long");
        exit(1);
    }

    //打开一个socket
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror(0);
        exit(1);
    }

    //将源IP地址写入请求
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror(0);
        shutdown(fd, SHUT_RDWR);//使用shutdown关闭socket连接，第二个参数：停止接受数据，写数据，或都停止
        exit(1);
    }
    struct sockaddr_in *source_ip_addr = (struct sockaddr_in *) &ifr.ifr_addr;
    memcpy(&req.arp_spa, &source_ip_addr->sin_addr.s_addr, sizeof(req.arp_spa));

    //将源MAC地址写入请求，SIOCGIFHWADDR指令为获取硬件地址
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror(0);
        shutdown(fd, SHUT_RDWR);
        exit(1);
    }
    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        fprintf(stderr, "Not an Ethernet interface");
        shutdown(fd, SHUT_RDWR);
        exit(1);
    }
    const unsigned char *source_mac_addr = (unsigned char *) ifr.ifr_hwaddr.sa_data;
    memcpy(header.ether_shost, source_mac_addr, sizeof(header.ether_shost));
    memcpy(&req.arp_sha, source_mac_addr, sizeof(req.arp_sha));
    shutdown(fd, SHUT_RDWR);//关闭socket，不需要再使用

    //将以太帧头部与ARP请求组合成完整请求，ether_header+ether_arp=frame
    unsigned char frame[sizeof(struct ether_header) + sizeof(struct ether_arp)]; //定义请求空间大小
    memcpy(frame, &header, sizeof(struct ether_header));                         //先组合以太帧头部
    memcpy(frame + sizeof(struct ether_header), &req, sizeof(struct ether_arp)); //再组合arp请求

    //对相应的网络接口打开一个PCAP实例
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0] = '\0';
    pcap_t *pcap = pcap_open_live(if_name, BUFSIZ, 1, 1000, pcap_errbuf);
    if (pcap_errbuf[0] != '\0') {
        fprintf(stderr, "%s\n", pcap_errbuf);
    }
    if (!pcap) {
        exit(1);
    }

    //将以太帧写入接口完成发包
    if (pcap_inject(pcap, frame, sizeof(frame)) == -1) {
        pcap_perror(pcap, 0);
        pcap_close(pcap);
        exit(1);
    }
    else {
        fprintf(stdout, "Send an ARP broadcast to get mac address who's IP address is [%s].\n", target_ip_string);
    }

    //关闭接口
    pcap_close(pcap);
}