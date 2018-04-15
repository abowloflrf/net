//
// Created by ruofeng on 18-4-15.
//
#include "device.h"
void print_all_deives()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices, *dev;

    if (pcap_findalldevs(&devices, error_buffer) != 0) {
        printf("Error finding device: %s\n", error_buffer);
        exit(0);
    }

    int i = 0;
    // pcap_findalldevs将找到本机所有接口保存在一个单向链表中
    //以下为对链表遍历输出对应的信息
    for (dev = devices; dev; dev = dev->next) {
        //列出正在运行的非回环接口 dev->flag==6
        if (dev->flags == 6) {
            //打印接口名
            printf("%d:%s", ++i, dev->name);
            if (i == 1)
                printf("\t%s", "Default device");
            //如果有描述则也输出
            if (dev->description) {
                printf("\t%s", dev->description);
            }
            putchar('\n');
        }
    }
    //释放所有的设备接口
    pcap_freealldevs(devices);
};

/// 获取本机默认设备接口
/// \return *pcap_if_t
pcap_if_t *get_default_dev()
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE] = {'\n'};
    pcap_if_t *devices, *dev;
    if (pcap_findalldevs(&devices, pcap_errbuf) != 0) {
        fprintf(stderr, "Failed to find any device: %s\n", pcap_errbuf);
        exit(0);
    }
    dev = devices;
    return dev;
}

void print_default_device_info(){
    char *dev;  /* name of the device to use */
    char *net;  /* dot notation of the network address */
    char *mask; /* dot notation of the network mask    */
    int ret;    /* return code */
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;  /* ip          */
    bpf_u_int32 maskp; /* subnet mask */
    struct in_addr addr;

    /* ask pcap to find a valid device for use to sniff on */
    dev = pcap_lookupdev(errbuf);

    /* error checking */
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    /* print out device name */
    printf("DEV: %s\n", dev);

    /* ask pcap for the network address and mask of the device */
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

    if (ret == -1) {
        printf("%s\n", errbuf);
        exit(1);
    }

    /* get the network address in a human readable form */
    addr.s_addr = netp;
    net = inet_ntoa(addr);

    if (net == NULL) /* thanks Scott :-P */
    {
        perror("inet_ntoa");
        exit(1);
    }

    printf("NET: %s\n", net);

    /* do the same as above for the device's mask */
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);

    if (mask == NULL) {
        perror("inet_ntoa");
        exit(1);
    }

    printf("MASK: %s\n", mask);
};