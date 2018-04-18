//
// Created by ruofeng on 18-4-15.
//

#ifndef NETWORK_LAB_PACKET_PRINTER_H
#define NETWORK_LAB_PACKET_PRINTER_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/types.h>

/// 解析抓取到的数据包并打印输出
/// \param packet
/// \param hdr
void printer(u_char *, const struct pcap_pkthdr *, const u_char *);

/// 解析输出以太帧头部信息，包括帧类型，目的mac地址，源mac地址
/// \param ether_header
void ethhdr_printer(struct ether_header *);

/// 解析输出arp帧信息，包括arp请求类型，Target IP，Sender IP
/// \param ether_arp
void arp_printer(struct ether_arp *);

#endif //NETWORK_LAB_PACKET_PRINTER_H

#pragma clang diagnostic pop