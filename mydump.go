package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func getdevices() {
	devices, _ := pcap.FindAllDevs()
	i := 0
	for x := range devices {
		i = i + 1
		_ = x
	}
	fmt.Println(i, " interfaces found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}

func printop(packetlen string, time string, srcmac string, dstmac string, ethtype string, srcip string, dstip string, protocol string, srcport string, dstport string, payload1 string, flags string, mtype uint16) {
	output := time
	output += " " + srcmac + "->" + dstmac + " type 0x" + ethtype + " len " + packetlen + " " + "\n"
	if ethtype != "806" {
		output += srcip + srcport + "->" + dstip + dstport + " " + flags
	}
	output += protocol + "\n"

	if len(payload1) != 0 {
		output += payload1
	}
	fmt.Println(output)

}

func packethandler(packet gopacket.Packet, string1 string, bpfstr string) {
	var srcmac string
	var dstmac string
	var ethtype string
	var srcip string
	var dstip string
	var protocol string
	var srcport string
	var dstport string
	var packetlen string
	var time string
	var payload1 string
	var syn bool
	var ack bool
	var psh bool
	var fin bool
	var rst bool
	var urg bool
	var flags string = ""
	var mtype uint16
	flag := 0

	// get packet length
	packetlen = packet.Dump()[21:24]
	packetlen = strings.TrimSpace(packetlen)
	packetlen = strconv.Itoa(packet.Metadata().Length)

	// get packet timestamp
	time = packet.String()[51:78]
	time = strings.TrimSpace(time)

	// get source MAC, destination MAC, Ethernet type from ethernet layer
	ethernetlayer := packet.Layer(layers.LayerTypeEthernet)
	//str := string(ethernetlayer.LayerPayload())
	//fmt.Println(str)
	if len(string1) != 0 && strings.Contains(string(ethernetlayer.LayerPayload()), string1) {
		flag = 1
		payload1 = hex.Dump(ethernetlayer.LayerPayload())
	}
	if ethernetlayer != nil {
		ethernetpacket, _ := ethernetlayer.(*layers.Ethernet)
		srcmac = ethernetpacket.SrcMAC.String()
		dstmac = ethernetpacket.DstMAC.String()

		ethtype1 := int64(ethernetpacket.EthernetType)
		ethtype = strconv.FormatInt(ethtype1, 16)
	}

	// get source IP, dest IP, protocol from IPV4 layer
	iplayer := packet.Layer(layers.LayerTypeIPv4)
	// if len(string1) != 0 && strings.Contains(string(iplayer.LayerPayload()), string1) {
	// 	flag = 1
	// 	payload1 = hex.Dump(iplayer.LayerPayload())
	// }
	if iplayer != nil {
		ippacket, _ := iplayer.(*layers.IPv4)
		srcip = ippacket.SrcIP.String()
		dstip = ippacket.DstIP.String()
		protocol = ippacket.Protocol.String()
		//fmt.Println(protocol)
		if len(string1) != 0 && strings.Contains(string(iplayer.LayerPayload()), string1) {
			flag = 1
			payload1 = hex.Dump(iplayer.LayerPayload())
		}
	}
	if protocol != "UDP" && protocol != "TCP" && protocol != "ICMPv4" {
		protocol = "OTHER"
	}
	iplayer1 := packet.Layer(layers.LayerTypeIPv6)
	// if len(string1) != 0 && strings.Contains(string(iplayer1.LayerPayload()), string1) {
	// 	flag = 1
	// 	payload1 = hex.Dump(iplayer1.LayerPayload())
	// }
	if iplayer1 != nil {
		ippacket, _ := iplayer.(*layers.IPv6)
		srcip = ippacket.SrcIP.String()
		dstip = ippacket.DstIP.String()
		if len(string1) != 0 && strings.Contains(string(iplayer1.LayerPayload()), string1) {
			flag = 1
			payload1 = hex.Dump(iplayer1.LayerPayload())
		}
	}

	udplayer := packet.Layer(layers.LayerTypeUDP)
	// if len(string1) != 0 && strings.Contains(string(udplayer.LayerPayload()), string1) {
	// 	flag = 1
	// 	payload1 = hex.Dump(udplayer.LayerPayload())
	// }
	if udplayer != nil {
		udppacket, _ := udplayer.(*layers.UDP)
		srcport = ":" + udppacket.SrcPort.String()
		dstport = ":" + udppacket.DstPort.String()
		if len(string1) != 0 && strings.Contains(string(udplayer.LayerPayload()), string1) {
			flag = 1
			payload1 = hex.Dump(udplayer.LayerPayload())
		}
	}

	// get source and destination ports from the tcp layer
	tcplayer := packet.Layer(layers.LayerTypeTCP)
	// if len(string1) != 0 && strings.Contains(string(tcplayer.LayerPayload()), string1) {
	// 	flag = 1
	// 	payload1 = hex.Dump(tcplayer.LayerPayload())
	// }
	if tcplayer != nil {
		tcppacket, _ := tcplayer.(*layers.TCP)
		srcport = ":" + tcppacket.SrcPort.String()
		dstport = ":" + tcppacket.DstPort.String()
		syn = bool(tcppacket.SYN)
		ack = bool(tcppacket.ACK)
		psh = bool(tcppacket.PSH)
		fin = bool(tcppacket.FIN)
		rst = bool(tcppacket.RST)
		urg = bool(tcppacket.URG)
		if syn {
			flags += "SYN "
		}
		if ack {
			flags += "ACK "
		}
		if psh {
			flags += "PSH "
		}
		if fin {
			flags += "FIN "
		}
		if rst {
			flags += "RST "
		}
		if urg {
			flags += "URG "
		}
		if len(string1) != 0 && strings.Contains(string(tcplayer.LayerPayload()), string1) {
			flag = 1
			payload1 = hex.Dump(tcplayer.LayerPayload())
		}
	}

	//print payload from application layer
	applicationlayer := packet.ApplicationLayer()
	if applicationlayer != nil {
		payload1 = hex.Dump(applicationlayer.Payload())
		if len(string1) != 0 && strings.Contains(string(applicationlayer.Payload()), string1) {
			flag = 1
			//printop(packetlen, time, srcmac, dstmac, ethtype, srcip, dstip, protocol, srcport, dstport, payload1)
		}
	}

	if len(string1) != 0 && flag == 1 {
		printop(packetlen, time, srcmac, dstmac, ethtype, srcip, dstip, protocol, srcport, dstport, payload1, flags, mtype)
	} else if len(string1) == 0 {
		printop(packetlen, time, srcmac, dstmac, ethtype, srcip, dstip, protocol, srcport, dstport, payload1, flags, mtype)
	}

}

func livecapture(interfaces string, string1 string, bpfstr string) {
	if handle, err := pcap.OpenLive(interfaces, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		handle.SetBPFFilter(bpfstr)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			packethandler(packet, string1, bpfstr) // Do something with a packet here.

		}
	}
}

func readpcap(pcapname string, string1 string, bpfstr string) {
	if handle, err := pcap.OpenOffline(pcapname); err != nil {
		panic(err)
	} else {
		handle.SetBPFFilter(bpfstr)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			packethandler(packet, string1, bpfstr) // Do something with a packet here.
		}
	}
}

func main() {
	devices, _ := pcap.FindAllDevs()

	var interfaces string = devices[0].Name
	var bpfstr string = ""
	var pcapname string
	var string1 string
	args1 := os.Args[1:]
	var ic = 0
	var sc = 0
	var rc = 0
	var bc = 0
	for i := 0; i < len(args1); i = i + 2 {
		if args1[i] == "-r" {
			if rc == 1 {
				fmt.Println("2 times -r not accepted")
				os.Exit(1)
			}
			rc = 1
			pcapname = args1[i+1]
			if strings.Contains(pcapname, " ") {
				fmt.Println("enter val after -r")
				os.Exit(1)
			}
			if pcapname == "-r" || pcapname == "-s" || pcapname == "-i" {
				fmt.Println("incorrect expression. enter value after -r")
				os.Exit(1)
			}
		} else if args1[i] == "-i" {
			if ic == 1 {
				fmt.Println("2 times -i not accepted")
				os.Exit(1)
			}
			ic = 1
			interfaces = args1[i+1]
			if interfaces == "-r" || interfaces == "-s" || interfaces == "-i" {
				fmt.Println("incorrect expression. enter value after -i")
				os.Exit(1)
			}
		} else if args1[i] == "-s" {
			if sc == 1 {
				fmt.Println("2 times -s not accepted")
				os.Exit(1)
			}
			sc = 1
			string1 = args1[i+1]
			if string1 == "-r" || string1 == "-s" || string1 == "-i" {
				fmt.Println("incorrect expression. enter value after -i")
				os.Exit(1)
			}
		} else {
			if bc == 1 {
				fmt.Println("2 times bpf not accepted")
				os.Exit(1)
			}
			bc = 1
			bpfstr = args1[i]
			i = i - 1
		}
	}

	_ = interfaces
	_ = string1
	_ = pcapname
	if len(pcapname) != 0 && len(interfaces) != 0 {
		fmt.Println("only -r will work")
		interfaces = ""
	}
	fmt.Println("interface= ", interfaces)
	fmt.Println("string1= ", string1)
	fmt.Println("pcapname= ", pcapname)
	fmt.Println("bpfstr= ", bpfstr)

	if len(pcapname) != 0 {
		readpcap(pcapname, string1, bpfstr)
	} else {
		livecapture(interfaces, string1, bpfstr)
	}

}
