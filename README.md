python-ulog2pcap
================

Python script to extract a pcap stream from a ULOG channel.

Usage
-----

First configure an iptables rule to log some packets to a ULOG channel:

```
$ iptables -A INPUT -s 1.2.3.4 -j ULOG --ulog-nlgroup 1
```

You can then grap packets written to the channel using ulog2pcap.py:

```
$ ulog2pcap.py 1 >packets.pcap
```

