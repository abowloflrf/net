//
// Created by ruofeng on 18-4-15.
//
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#ifndef NETWORK_LAB_DEVICE_H
#define NETWORK_LAB_DEVICE_H

void print_all_deives();

/// 获取本机默认设备接口
/// \return *pcap_if_t
pcap_if_t *get_default_dev();

void print_default_device_info();

#endif //NETWORK_LAB_DEVICE_H
