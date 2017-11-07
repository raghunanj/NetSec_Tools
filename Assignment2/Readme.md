`Goal` :To develop a passive network monitoring application
written in C (or C++, but no other language is acceptable) using the libpcap
packet capture library. Your program, called 'mydump', will capture the
traffic from a network interface in promiscuous mode (or read the packets from
a pcap trace file) and print a record for each packet in its standard output,
much like a simplified version of tcpdump. The user should be able to specify
a BPF filter for capturing a subset of the traffic, and/or a string pattern
for capturing only packets with matching payloads.

Your program should conform to the following specification:

`mydump [-i interface] [-r file] [-s string] expression`

-i  Live capture from the network device <interface> (e.g., eth0). If not
    specified, mydump should automatically select a default interface to
    listen on (hint 1). Capture should continue indefinitely until the user
    terminates the program.

-r  Read packets from <file> in tcpdump format (hint 2).

-s  Keep only packets that contain <string> in their payload (after any BPF
    filter is applied). You are not required to implement wildcard or regular
    expression matching. A simple string matching operation should suffice
    (hint 3).

<expression> is a BPF filter that specifies which packets will be dumped. If
no filter is given, all packets seen on the interface (or contained in the
trace) should be dumped. Otherwise, only packets matching <expression> should
be dumped.

For each packet, mydump prints a record containing the timestamp, source and
destination MAC address, EtherType, packet length, source and destination IP
address and port, protocol type (e.g., "TCP", "UDP", "ICMP", "OTHER"), and the
raw content of the packet payload (hint 4). You are free, but not required, to
enrich the output with other useful information from the packet headers (e.g.,
TCP flags, IP/TCP options, ICMP message types). You do not need to support any
link-layer protocol other than Ethernet.
