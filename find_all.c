#include <arpa/inet.h>
#include <net/if_dl.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

int main(int argc, char** argv) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices, *dev;

    if (pcap_findalldevs(&devices, error_buffer) != 0) {
        printf("Error finding device: %s\n", error_buffer);
        return 0;
    }
    int i = 0;
    // pcap_findalldevs将找到本机所有接口保存在一个单向链表中
    //以下为对链表遍历输出对应的信息
    for (dev = devices; dev; dev = dev->next) {
        //列出正在运行的非回环接口 dev->flag==6
        if (dev->flags == 6) {
            //打印接口名
            // printf("%d:%s\n", ++i, dev->name);
            //获取接口地址
            pcap_addr_t* address = dev->addresses;
            struct sockaddr* sa_addr = address->addr;
            //链路层地址
            if (sa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl* link_addr = (struct sockaddr_dl*)sa_addr;
                struct in_addr;
                char* linkAddress = link_ntoa(link_addr);
                //打印MAC地址
                printf("%d.  %s\n", ++i, linkAddress);
            }
            //如果有描述则也输出
            if (dev->description) {
                printf("%s\n", dev->description);
            }
        }
    }
    //释放所有的设备接口
    pcap_freealldevs(devices);
    return 0;
}