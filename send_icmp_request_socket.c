//
// Created by ruofeng on 18-4-15.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

#include <netinet/ip_icmp.h>
#include <arpa/inet.h> //inet_pton
#include <unistd.h>  //getpid
#include <errno.h>

#define BUFSIZE 1500

/// 计算icmp校验和
/// \param addr icmp报文结构体指针
/// \param len icmp报文长度，包含至少8位的头部与后面的data
/// \return
unsigned short check_sum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short) ~sum;
    return answer;
}

/// 填充icmp报文
/// \param icmp_sequ
/// \param msg
/// \return icmp struct
struct icmp *fill_icmp_packet(uint16_t icmp_sequ, char *msg)
{
    struct icmp *icmp;                              //新建icmp报文指针
    char sendbuf[BUFSIZE];                          //发送包缓冲区，最大大小为1500
    icmp = (struct icmp *) sendbuf;                 //将icmp指针指向发送包缓冲区
    icmp->icmp_type = ICMP_ECHO;                    //icmp echo请求
    icmp->icmp_code = 0;                            //code字段再请求时无意义，填充为0
    icmp->icmp_cksum = 0;                           //校验和先填充为0，后面再计算并填充
    icmp->icmp_seq = icmp_sequ;                     //icmp序列
    icmp->icmp_id = (uint16_t) getpid();            //icmp id填入进程id
    int msglen = (int) strlen(msg);                 //要发送的信息长度
    memcpy(sendbuf + 8, msg, (size_t) msglen + 1);  //在icmp必须的8字节之后填入要发送的信息
    icmp->icmp_cksum = check_sum((unsigned short *) icmp, ICMP_MINLEN + msglen + 1);    //填充校验和
    return icmp;
}

int main(int argc, char **argv)
{
    //必须接受一个参数，目的IP地址
    if (argc < 2) {
        printf("Usage: ./SendIcmpRequestPcap <ip addr>\n");
        exit(1);
    }
    const char *target_ip_str = argv[1];

    //获取可选的第二个参数，发送消息
    char *send_msg = "Hello from the other side.";
    if (argc > 2) {
        send_msg = argv[2];
    }
    size_t a = strlen(send_msg);
    char msg[a + 1];
    strncpy(msg, send_msg, a + 1);

    //定义数据结构
    struct sockaddr_in dst_addr;    //目的IP地址结构体
    struct icmp *icmp_packet;       //icmp包指针
    int sockfd;                     //socket
    char buf[BUFSIZE];              //可发送最大数据包

    //将目的IP地址填充到sockaddr_in结构体中
    bzero(&dst_addr, sizeof(struct sockaddr_in));
    dst_addr.sin_family = AF_INET;
    //填充IP地址时防止无效IP
    if (inet_pton(AF_INET, target_ip_str, &(dst_addr.sin_addr)) == 0) {
        fprintf(stderr, "%s is not a valid IP address\n", target_ip_str);
        exit(1);
    }

    //填充ICMP包，序列号设置为1，发送的消息为msg
    icmp_packet = fill_icmp_packet(1, msg);
    //将返回的ICMP包填充到buf中
    memcpy(buf, icmp_packet, ICMP_MINLEN + sizeof(msg));

    //建立socket
    if (!(sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP))) {
        perror("Unable to open raw socket\n");
        exit(0);
    }

    //发送ICMP数据包
    int retno = (int) sendto(sockfd,
                             buf,
                             ICMP_MINLEN + sizeof(msg),
                             0,
                             (struct sockaddr *) &dst_addr,
                             sizeof(struct sockaddr_in));

    //发送错误并返回
    if (retno == -1) {
        fprintf(stderr, "Error sending: %i\n", errno);
        exit(0);
    }
    else {
        //发送成功
        printf("Send ICMP packet to %s with message: [%s]\n", target_ip_str, msg);
    }

    //关闭socket
    shutdown(sockfd, SHUT_RDWR);

    return 0;
}
