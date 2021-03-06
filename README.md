# linux-gre-keepalive

Userspace daemon in perl to handle Cisco GRE keepalives. Works in Linux, should work in any *nix derivative

Requires Net::Pcap, NetPacket::IP, and Proc::Daemon

(all 3 have stable debian perl packages in the standard repositories)

This daemon does not initiate keepalive packets, but does look for ones sent by the originating system and redirects them as a standard Cisco router would, thus causing the GRE tunnel to go up/up, and causing it to go up/down if connectivity is lost. 

## Usage:

    sysctl -w net.ipv4.ip_forward=1

    sysctl -w net.ipv6.conf.all.forwarding=1

    ip tunnel add mytunnel mode gre remote x.x.x.x local y.y.y.y ttl 255 pmtudisc

    ip link set mytunnel up

    ./gre-keepalive.pl mytunnel

## systemd

1. Install script and systemd unit

```
cp gre-keepalive.pl /usr/local/sbin/
cp gre-keepalive@.service /usr/lib/systemd/system/
```

2. Start and enable the service(s)

```
systemctl start gre-keepalive@mytunnel1
systemctl enable gre-keepalive@mytunnel1

systemctl start gre-keepalive@mytunnel2
systemctl enable gre-keepalive@mytunnel2
```
