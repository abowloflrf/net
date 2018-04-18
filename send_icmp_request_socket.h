//
// Created by ruofeng on 18-4-18.
//

#ifndef NETWORK_LAB_SEND_ICMP_REQUEST_SOCKET_H
#define NETWORK_LAB_SEND_ICMP_REQUEST_SOCKET_H

/// 计算icmp校验和
/// \param addr icmp报文结构体指针
/// \param len icmp报文长度，包含至少8位的头部与后面的data
/// \return
unsigned short check_sum(unsigned short *addr, int len);

/// 填充icmp报文
/// \param icmp_sequ
/// \param msg
/// \return icmp struct
struct icmp *fill_icmp_packet(uint16_t icmp_sequ, char *msg);

/// 发送ICMP数据包
/// \@param target_ip_str 目标IP地址
/// \@param send_data 发送数据，可选
void send_icmp(char *target_ip_str, char *send_data);

#endif //NETWORK_LAB_SEND_ICMP_REQUEST_SOCKET_H
