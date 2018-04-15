# Net Lab

## Require Libraries

*   libpcap

## Executable

All excutable binary files built from CMakeLists.txt

### Capture

Capture ARP/TCP/ICMP requests

```
sudo ./Capture
```

### SendArpRequestPcap

Send an ARP broadcast request from a specified device interface to get the MAC address who holds the IP address

```
sudo ./SendArpRequestPcap <device interface> <ip addr>
```
