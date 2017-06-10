package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

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
	handleTermination()

	handle.SetBPFFilter(bpfFilter)

	doubleShapeOutput := "node [shape = doublecircle]; "

	for _, addr := range dev.Addresses {
		doubleShapeOutput += fmt.Sprintf("\"%v\";", addr.IP)
	}
	doubleShapeOutput += "\n"

	fmt.Printf("digraph interface_capture { \n\t rankdir=LR; \n\t size=\"66\" \n\t %v \"%v\"; \n\t node [shape = circle]; \n", doubleShapeOutput, dev.Addresses[1].IP.String())

	var ips []string

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ip := ipLayer.(*layers.IPv4)
				if ip != nil {
					srcDst := ip.SrcIP.String() + ip.DstIP.String()

					if contains(ips, srcDst) == false {
						//fmt.Printf("\"%v:%v\" -> \"%v:%v\";\n", ip.SrcIP.String(), tcp.SrcPort.String(), ip.DstIP.String(), tcp.DstPort.String())
						fmt.Printf("\t \"%v\" -> \"%v\" [ label = \"%v\" ];\n", ip.SrcIP.String(), ip.DstIP.String(), tcp.DstPort.String())
						ips = append(ips, srcDst)
					}
				}
			}
		}
	}
}

func handleTermination() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("}")
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
