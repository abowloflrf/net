//
// Created by ruofeng on 18-4-15.
//

#include "capture.h"
void capture()
{
    char errbuf[PCAP_ERRBUF_SIZE] = {'\0'};
    pcap_if_t *dev;
    struct bpf_program fp;
    char filter_exp[] = "(icmp or arp) and ether src 9c:b6:d0:d3:b8:5d";
    //char filter_exp[] = "arp && ether src 9c:b6:d0:d3:b8:5d";    //过滤表达式，这里过滤的是源地址为开发机器(DELL XPS13)的ARP数据包

    //直接获取默认设备
    dev = get_default_dev();
    fprintf(stdout, "Capturing packet using default device: %s\n\n", dev->name);

    //pcap_open_live:打开一个设备准备抓包
    //参数：0-设备名 1-捕获字节数 2-开启混杂模式 3-连接超时时间 4-错误输出缓冲
    pcap_t *pcap = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (!pcap) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
        exit(0);
    }
    //pcap_compile:将过滤表达式编译打包成可用的过滤程序，并输出到fp
    //参数：0-pcap实例，1-保存pcap过滤程序的结构体指针，2-过滤表达式字符串，3-是否优化，4-掩码，若不进行广播操作可设置为未知
    if (pcap_compile(pcap, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        exit(0);
    }
    //pcap_setfilter:为pcap实例设置一个编译好的过滤程序
    //参数：0-pcap实例，1-保存pcap过滤程序的结构体指针
    if (pcap_setfilter(pcap, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        exit(0);
    }

    //循环抓取10个包，got_packet为回调函数
    pcap_loop(pcap, 10, printer, NULL);

    //关闭pcap停止抓包并退出
    pcap_freecode(&fp);
    pcap_close(pcap);
}

