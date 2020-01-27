# IP Changer
## How To Use
> Don't forget to reset iptables settings after using this program `sudo iptables -F`
1. Setup netfilter using iptables `./set_netfilter_queue.sh` or `./set_netfilter_queue_nat.sh`
2. Start IP Changer `./IpChanger  [Destination IP] [Destination Port]`

## Supported OS
- Linux

## Dependencies
- [libnetfilter_queue]: For change packet data in-path.
- [libglog]: For logging.

[libnetfilter_queue]: https://netfilter.org/projects/libnetfilter_queue/
[libglog]: https://github.com/google/glog
