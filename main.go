package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"io/ioutil"
	"os/exec"

	"flag"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var pack packetHolder
var vGraph VizceralNode
var localIp, bpfFilter, outputFile string

const (
	internet     = "INTERNET"
	focusedChild = "focusedChild"
	normal       = "normal"
	region       = "region"
)

func init() {
	flag.StringVar(&bpfFilter, "filter", "tcp", "filter=\"tcp and udp\"")
	flag.StringVar(&outputFile, "out", "/tmp/generated.json", "out=/path/to/file.json")
	flag.Parse()
}

func main() {
	pack = packetHolder{}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) < 2 {
		log.Fatal("BPF filter must be specified as first argument. Eg: sudo ./network-logger \"tcp and udp\"")
	}

	bpfFilter = os.Args[1]

	dev := devices[0]
	handle, err := pcap.OpenLive(dev.Name, int32(65535), false, time.Second*-1)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	handleTermination()

	handle.SetBPFFilter(bpfFilter)

	var ips []string
	for _, addr := range dev.Addresses {
		if len(addr.IP) > 4 {
			continue
		}
		ips = append(ips, addr.IP.String())
	}

	localIp = ips[0]

	vGraph = MakeVizceralNode(localIp)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			parseIPLayer(packet, &vGraph.Nodes[1])
		}
	}
}

func parseIPLayer(packet gopacket.Packet, vn *VizceralNode) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		if ip != nil {
			srcDst := ip.SrcIP.String() + ip.DstIP.String()
			pack.Lock()
			defer pack.Unlock()
			if contains(pack.packetSources, srcDst) == false {
				srcIp := ip.SrcIP.String()
				dstIp := ip.DstIP.String()

				if srcIp != localIp && dstIp == localIp {
					srcIp = localIp
					dstIp = ip.SrcIP.String()
				}

				if srcIp == localIp {
					srcIp = "local"
				}

				srcNode := VizceralNode{
					Name:     srcIp,
					Renderer: focusedChild,
					Class:    normal,
				}

				dstNode := VizceralNode{
					Name:     dstIp,
					Renderer: focusedChild,
					Class:    normal,
				}

				vn.Nodes = append(vn.Nodes, srcNode, dstNode)
				newConnection := VizceralConnection{
					Source: srcNode.Name,
					Target: dstNode.Name,
					Class:  normal,
					Metrics: &VizceralMetric{
						Normal: 100,
						Danger: 20,
					},
				}
				vn.Connections = append(vn.Connections, newConnection)
				pack.packetSources = append(pack.packetSources, srcDst)

				log.Println("Added node")
			}
		}
	}
}

func handleTermination() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		jsonResult := vGraph.String()
		log.Println(jsonResult)

		trySavingToFile(jsonResult)
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

func trySavingToFile(jsonResult string) {
	if outputFile != "" {
		ioutil.WriteFile(outputFile, []byte(jsonResult), 0666)
		cmd := exec.Command("chown", "stefanszasz", outputFile)
		_, err := cmd.Output()
		if err != nil {
			log.Fatal(err)
		}
	}
}
