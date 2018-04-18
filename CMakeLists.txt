project(network-lab)
cmake_minimum_required(VERSION 2.6)
set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")

# 根目录
aux_source_directory(. DIR_MAIN)

add_executable(Main main.c capture.c device.c packet_printer.c send_arp_request_pcap.c send_icmp_request_socket.c)
target_link_libraries(Main pcap)