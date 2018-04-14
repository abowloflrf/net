project(leetcode)
cmake_minimum_required(VERSION 2.6)
set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")
set(CMAKE_CXX_STANDARD 11)

# 根目录
aux_source_directory(. DIR_MAIN)

add_executable(ListDev list_dev.c)
target_link_libraries(ListDev pcap)

add_executable(FindAll find_all.c)
target_link_libraries(FindAll pcap)

add_executable(SendArpRequestSocket send_arp_request_socket.c)

add_executable(SendArpRequestPcap send_arp_request_pcap.c)
target_link_libraries(SendArpRequestPcap pcap)
