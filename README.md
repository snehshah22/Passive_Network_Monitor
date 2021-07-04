# Passive_Network_Monitor
Application captures the traffic from a network interface in promiscuous mode or reads the packets from a pcap trace file and prints a record for each packet in its standard output.

Specification
go run mydump.go [-i interface] [-r file] [-s string] [BPF expression]

Usage:
The code takes 4 parameters

1) -i interface.
The interface to be monitored can be specified. Default interface is found by FindAllDevs, if no interface is specified. Invalid interface 
name will produce errors.

2) -r pcapname
Pcap file can also be read by this network monitoring application. A corrupted or erroneous file will produce errors.

3) -s string
If a particular string is provided, then only the packets which contain the specified string in the payload will be printed. Payloads of
each layer will be checked and only the last layer with the provided payload will be printed.

4) BPF expression
If a BPF expression (Eg. src, dst, protocol etc) is provided, then the network traffic will be filtered based on the filter expression.

If both interface and pcapname is mentioned, then pcap file will be read.
If none of the interface name and pcapname are mentioned then the network sniffing will be done over the interface by default.
Default interface is found by FindAllDevs.
Just like tcpdump, there is no particular order in which the parameters need to be entered.
The program needs to run in sudo to avoid permission realted errors.

Implementation Details:
Once all the parameters are gathered from the command line arguments, there a the following main functions which are used
- readpcap (for reading the pcapfile)
- livecapture (for live packet traffic monitoring)
- packethandler (for extracting packet related information)
- printop (printing packet data)

The functions are explained in detail below
- readpcap: Handles the offline traffic monitoring. BFP filter is also applied here to filter onlt the required traffic. 
- livecapture: Handles the online traffic monitoring. BFP filter is also applied here to filter onlt the required traffic. 
- packethandler: 
*Ethernet Layer: Src and Dest MAC address and ethernet type are extracted from this layer.
*IP Layer(v4 and v6): Src and Dest IP and protocol are extracted from the layer.
*TCP Layer: Src and Dest port and TCP flags are extracted from this layer.
*UDP Layer: Src and Dest port of UDP packets.
Other than these parameters, the payload is also checked at each layer.
- printop: Is used to print the output in the format specified in the hw2.txt file.

Please refer sample_op.txt to see the sample outputs.
