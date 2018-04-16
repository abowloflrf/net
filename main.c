//
// Created by ruofeng on 18-4-16.
//

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

int main(int argc, char **argv)
{
    //保存flag的数据结构
    struct globalArgs_t
    {
        int isCapture;
        int isSendARP;
        int isSendICMP;
        char *targetIP;
        char *arpDevice;
        char *icmpData;
    } globalArgs = {0, 0, 0, NULL, NULL, NULL};

    //getopt配置
    const char *optstring = "caid:t:m:";
    struct option opts[] = {
        {"capture", no_argument, NULL, 'c'},
        {"arp", no_argument, NULL, 'a'},
        {"icmp", no_argument, NULL, 'i'},
        {"dev", required_argument, NULL, 'd'},
        {"target", required_argument, NULL, 't'},
        {"msg", required_argument, NULL, 'm'}
    };
    int c;
    while ((c = getopt_long(argc, argv, optstring, opts, NULL)) != -1) {
        switch (c) {
        case 'c':globalArgs.isCapture = 1;
            break;
        case 'a':globalArgs.isSendARP = 1;
            break;
        case 'd':globalArgs.arpDevice = optarg;
            break;
        case 't':globalArgs.targetIP = optarg;
            break;
        case 'i':globalArgs.isSendICMP = 1;
            break;
        case 'm':globalArgs.icmpData = optarg;
            break;
        case '?':printf("Unknown option\n");
            exit(0);
        default:printf("Who are you?\n");
        }
    }
    //抓包
    if (globalArgs.isCapture) {
        printf("Capturing packet...\n");
        return 0;
    }
    //发送ARP包，必须包含两个参数，设备名与目标IP
    if (globalArgs.isSendARP) {
        if (globalArgs.arpDevice && globalArgs.targetIP)
            printf("Send ARP packet via [%s] to get [%s]'s mac address\n",
                   globalArgs.arpDevice,
                   globalArgs.targetIP);
        else {
            fprintf(stderr, "Arguments error, please check.\n");
            exit(0);
        }
        return 0;
    }
    //发送ICMP包，至少包含一个参数IP地址，可选第二个参数，发送数据
    if (globalArgs.isSendICMP) {
        if (globalArgs.targetIP)
            printf("Send ICMP packet to [%s] with data [%s]\n",
                   globalArgs.targetIP,
                   globalArgs.icmpData);
        else {
            fprintf(stderr, "Arguments error, please check.\n");
            exit(0);
        }
        return 0;
    }

    return 0;
}