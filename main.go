package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var packetSources []string

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) < 2 {
		log.Fatal("BPF filter must be specified as first argument. Eg: sudo ./network-logger \"tcp and udp\"")
	}

	bpfFilter := os.Args[1]

	dev := devices[0]
	handle, err := pcap.OpenLive(dev.Name, int32(65535), false, time.Second*-1)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	formatter := &GraphVizFormatter{}

	handleTermination(formatter)

	handle.SetBPFFilter(bpfFilter)

	var ips []string
	for _, addr := range dev.Addresses {
		ips = append(ips, addr.IP.String())
	}

	doubleShapeOutput := formatter.Header(ips)

	fmt.Printf(doubleShapeOutput)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			parseIPLayer(packet, tcp.DstPort.String(), formatter)
		}
	}
}

func parseIPLayer(packet gopacket.Packet, dstPort string, formatter OutputFormatter) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		if ip != nil {
			srcDst := ip.SrcIP.String() + ip.DstIP.String()

			if contains(packetSources, srcDst) == false {
				entry := &PacketEntry{DestinationPort: dstPort, DestinationIP: ip.DstIP.String(), SourceIp: ip.SrcIP.String()}
				fmt.Printf(formatter.Entry(entry))
				packetSources = append(packetSources, srcDst)
			}
		}
	}
}

func handleTermination(formatter OutputFormatter) {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Printf(formatter.Footer())
		os.Exit(0)
	}()
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
