project(network-lab)
cmake_minimum_required(VERSION 2.6)
set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")

# 根目录
aux_source_directory(. DIR_MAIN)

add_executable(SendArpRequestSocket send_arp_request_socket.c)

add_executable(SendArpRequestPcap send_arp_request_pcap.c)
target_link_libraries(SendArpRequestPcap pcap)

#add_executable(SendArpReplyPcap send_arp_reply_pcap.c)
#target_link_libraries(SendArpReplyPcap pcap)

add_executable(Capture capture.c device.c packet_printer.c)
target_link_libraries(Capture pcap)
