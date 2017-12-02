# NetSec_Tools

1. Passive Network Monitoring tool.

A passive network monitoring application written in C using the libpcap packet capture library which will capture the traffic from a network interface in promiscuous mode (or read the packets from a pcap trace file) and print a record for each packet in its standard output, much like a simplified version of tcpdump. The user should be able to specify
a BPF filter for capturing a subset of the traffic, and/or a string pattern for capturing only packets with matching payloads.

2. Plugboard Proxy tool.

A "plugboard" proxy for adding an extra layer of protection to publicly accessible network services.
