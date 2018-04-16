# Net Lab

[![Build Status](https://travis-ci.org/abowloflrf/net.svg?branch=master)](https://travis-ci.org/abowloflrf/net)

## Require Libraries

*   libpcap

## Executable

All excutable binary files built from CMakeLists.txt

### Capture

Capture ARP/TCP/ICMP requests(TCP and ICMP packet parser is not completed yet).

```
sudo ./Capture
```

### SendArpRequestPcap

Send an ARP broadcast request from a specified device interface to get the MAC address who holds the IP address.

```
sudo ./SendArpRequestPcap <device interface> <ip addr>
```

### SendIcmpRequestSocket

Send ICMP echo request with custom data string.

```
sudo ./SendIcmpRequestSocket <ip addr> <data>
```
