#include <pcap.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices, *dev;

    if (pcap_findalldevs(&devices, error_buffer) != 0) {
        printf("Error finding device: %s\n", error_buffer);
        return 0;
    }

    int i= 0;
    // pcap_findalldevs将找到本机所有接口保存在一个单向链表中
    //以下为对链表遍历输出对应的信息
    for (dev = devices; dev; dev = dev->next) {
        //列出正在运行的非回环接口 dev->flag==6
        if (dev->flags == 6) {
            //打印接口名
            printf("%d:%s", ++i, dev->name);
            //如果有描述则也输出
            if (dev->description) {
                printf("\t%s", dev->description);
            }
            putchar('\n');
        }
    }
    //释放所有的设备接口
    pcap_freealldevs(devices);
    return 0;
}