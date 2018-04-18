# Net Lab

[![Build Status](https://travis-ci.org/abowloflrf/net.svg?branch=master)](https://travis-ci.org/abowloflrf/net)

## Required Libraries

*   libpcap

If you are using Ubuntu/Debian you can install `libpcap` by apt command: 

```
sudo apt install libpcap-dev
```
 
## Build

```
git clone https://github.com/abowloflrf/net.git
cd net
mkdir build && cd build
cmake ..
make
```

## Usage

### Capture

Capture ARP/TCP/ICMP requests(TCP and ICMP packet parser is not completed yet).

```
sudo ./Main --capture
```

You have to set the pcap filter string in `capture.c`:

```c
char filter_exp[] = "(icmp or arp) and ether src 9c:b6:d0:d3:b8:5d";
```

### SendArpRequestPcap

Send an ARP broadcast request from a specified device interface to get the MAC address who holds the IP address.

```
sudo ./Main --arp --dev <device interface> --target <ip addr>
```

### SendIcmpRequestSocket

Send ICMP echo request with custom data string.

```
sudo ./Main --icmp --target <ip addr> --msg <data>
```
