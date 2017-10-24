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

	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	ethLayer                                          layers.Ethernet
	iPv4                                              layers.IPv4
	tcpLayer                                          layers.TCP
	pack                                              packetHolder
	vGraph                                            VizceralNode
	localIp, bpfFilter, outputFile, devName, hostName string
	packetTimeMap                                     map[string][]time.Time
)

const (
	internet     = "INTERNET"
	focusedChild = "focusedChild"
	normal       = "normal"
	region       = "region"
)

func init() {
	flag.StringVar(&bpfFilter, "filter", "tcp", "filter=\"tcp and udp\"")
	flag.StringVar(&outputFile, "out", "/tmp/generated.json", "out=/path/to/file.json")
	flag.StringVar(&devName, "dev", "", "dev=en0")

	flag.Parse()
	hostName = getSimpleHostname()
}

func main() {
	var dev pcap.Interface
	packetTimeMap = make(map[string][]time.Time)
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) < 2 {
		log.Fatal("BPF filter must be specified as first argument. Eg: sudo ./network-logger \"tcp and udp\"")
	}

	if devName == "" {
		dev = devices[0]
		devName = dev.Name
	} else {
		for _, d := range devices {
			if d.Name == devName {
				dev = d
				break
			}
		}
	}

	handle, err := pcap.OpenLive(dev.Name, int32(65535), false, time.Second*-1)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	handleTermination()

	handle.SetBPFFilter(bpfFilter)

	var ips []string
	for _, addr := range dev.Addresses {
		if len(addr.IP) > 4 { //we don't use IPv6 yet
			continue
		}
		ips = append(ips, addr.IP.String())
	}

	localIp = ips[0]

	vGraph = MakeRootVizceralNode(hostName)

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

			srcIp := ip.SrcIP.String()
			dstIp := ip.DstIP.String()

			if srcIp != localIp && dstIp == localIp {
				srcIp = localIp
				dstIp = ip.SrcIP.String()
			}

			if srcIp == localIp {
				srcIp = hostName
			}

			srcDst = srcIp + dstIp

			parser := gopacket.NewDecodingLayerParser(
				layers.LayerTypeEthernet,
				&ethLayer,
				&iPv4,
				&tcpLayer,
			)
			foundLayerTypes := []gopacket.LayerType{}

			_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)

			for _, layerType := range foundLayerTypes {
				if layerType == layers.LayerTypeTCP {
					if tcpLayer.SYN && tcpLayer.ACK {
						log.Println("SYN + ACK")
					}
				}
			}

			packetNewRemote := len(packetTimeMap[srcDst]) == 0
			srcDstCount := 1.0
			packetTimeMap[srcDst] = append(packetTimeMap[srcDst], time.Now())

			if packetNewRemote {
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
						Normal: srcDstCount,
						Danger: 0,
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
		vGraph.Nodes[1].Name = hostName

		connections := vGraph.Nodes[1].Connections

		for _, con := range connections {
			conKey := con.Source + con.Target
			timeSlices := packetTimeMap[conKey]
			if len(timeSlices) > 1 {
				timeFrames := packetTimeMap[conKey]
				sFrame := timeFrames[0]
				eFrame := timeFrames[len(timeFrames)-1]
				secondsDiff := eFrame.Sub(sFrame).Seconds()

				packPerSec := float64(len(packetTimeMap[conKey])) / secondsDiff
				con.Metrics.Normal = packPerSec
				log.Printf("RPS: %.2f", packPerSec)
			}
		}

		jsonResult := vGraph.String()
		log.Println(jsonResult)

		trySavingToFile(jsonResult)
		os.Exit(0)
	}()
}

func trySavingToFile(jsonResult string) {
	if outputFile != "" {
		fmt.Println("Saving to file")
		ioutil.WriteFile(outputFile, []byte(jsonResult), 0666)
		cmd := exec.Command("chown", "stefanszasz", outputFile)
		_, err := cmd.Output()
		if err != nil {
			log.Fatal("Error when saving to file: " + err.Error())
		}
		fmt.Println("Saved to: " + outputFile)
	}
}

func getSimpleHostname() string {
	h, err := os.Hostname()
	if err == nil {
		return h
	}

	return "local"
}
