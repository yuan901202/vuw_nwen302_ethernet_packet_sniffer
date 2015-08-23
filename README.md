# ethernet_packet_sniffer
[NWEN302] Ethernet Packet Sniffer in C

## Overall:
This C program is using pcap library to implement the Ethernet Packet Sniffer tool in C. The Ethernet packet sniffer is very important to network engineer to identify the potential bugs within networks, and it can testing the program communication between server and clients, and also it can used to monitor the network traffic.

## Functions:
The following function can be achieved by this C program:
(1) Identify IPv4, IPv6 and other types of ethernet traffic.
(2) Identify TCP, UDP, ICMP, ICMPv6 and other protocols.

- IPv4 traffic
    - TCP
    - UDP
    - ICMP
    - unknown
- IPv6 traffic
    - IPv6 extension headers
    - TCP
    - UDP
    - ICMPv6
    - unknown
- Other types of Ethernet traffic

## Installed requirements:

### Hardware

A machine with Internet connection, and NIC (Network Interface Controller) should be
working.

### Software

A working machine should completed installed with following software:

(1) libpacp or winpacp (for windows user) successful installed;

(2) tcpdump or similar software installed;

(3) Standard C library installed;

(4) BSD UNIX Socket library installed;

(5) Working C complier, like GCC;

(6) Wireshark or similar software installed; and

(7) The Terminal (Linux, Mac) or CMD/MS-DOS (Windows) should be working.

## Notice:
This program only support anaylse the **.pcap captured file that you use tcpdump or Wireshark.
pcap_open_offline() is used in this program.

## Running it:

### First, you need to capture a packet file:
$ tcpdump -s0 -w file_name
OR use Wireshark to capture packet

### Then, you need compile C program and link to pcap libray:
$ gcc -o eps eps.c -l pcap

### Next, you could running the program to analyse the captured file that you captured before:
$ ./eps file_name

### Finally, you can compare the result with using Wireshark:
$ wireshark file_name

## Credit give to:
Tim Carstens' "sniffer.c" demonstration source code (http://www.tcpdump.org/sniffex.c).
