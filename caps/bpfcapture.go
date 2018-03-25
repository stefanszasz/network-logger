package caps

import (
	"errors"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketCounter struct {
	Count      int
	Start, End time.Time
	Err        int
}

// BPFCapture processes network packets from the specified device using bpfFilter
type BPFCapture struct {
	Device                         string
	ethLayer                       layers.Ethernet
	iPv4                           layers.IPv4
	tcpLayer                       layers.TCP
	pack                           packetHolder
	localIp, bpfFilter, outputFile string
	devName, hostName, fileOwner   string
	retransmits                    map[uint32]bool
}

type BPFCaptureInput struct {
	Device, Filter, Source string
}

type BPFCaptureResult struct {
	Result        string
	VizceralNode  *VizceralNode
	PacketTimeMap map[string]PacketCounter
}

func MakeNewBPFCapture(in *BPFCaptureInput) *BPFCapture {
	return &BPFCapture{Device: in.Device, retransmits: make(map[uint32]bool)}
}

func (b BPFCapture) StartCapture(ch chan VizceralNode) (interface{}, error) {
	var dev pcap.Interface

	res := &BPFCaptureResult{
		PacketTimeMap: make(map[string]PacketCounter),
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	if len(os.Args) < 2 {
		return nil, errors.New("BPF filter must be specified as first argument. Eg: sudo ./network-logger \"tcp and udp\"")
	}

	if b.Device == "" {
		dev = devices[0]
		b.Device = dev.Name
	} else {
		for _, d := range devices {
			if d.Name == b.Device {
				dev = d
				break
			}
		}
	}

	handle, err := pcap.OpenLive(b.Device, int32(65535), false, time.Second*-1)
	if err != nil {
		return nil, err
	}

	defer handle.Close()

	handle.SetBPFFilter(b.bpfFilter)

	var ips []string
	for _, addr := range dev.Addresses {
		if len(addr.IP) > 4 { //we don't use IPv6 yet
			continue
		}
		ips = append(ips, addr.IP.String())
	}

	b.localIp = ips[0]

	res.VizceralNode = MakeRootVizceralNode(b.hostName)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			b.parseIPLayer(packet, &res.VizceralNode.Nodes[1], res, ch)
		}
	}

	return res, nil
}

func (b BPFCapture) parseIPLayer(packet gopacket.Packet, vn *VizceralNode, res *BPFCaptureResult, ch chan VizceralNode) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		if ip != nil {
			srcDst := ip.SrcIP.String() + ip.DstIP.String()

			srcIp := ip.SrcIP.String()
			dstIp := ip.DstIP.String()

			if srcIp != b.localIp && dstIp == b.localIp {
				srcIp = b.localIp
				dstIp = ip.SrcIP.String()
			}

			if srcIp == b.localIp {
				srcIp = b.hostName
			}

			srcDst = srcIp + dstIp

			p := res.PacketTimeMap[srcDst]
			newRemotePacket := p.Count == 0
			p.Count++

			parser := gopacket.NewDecodingLayerParser(
				layers.LayerTypeEthernet,
				&b.ethLayer,
				&b.iPv4,
				&b.tcpLayer,
			)
			var foundLayerTypes []gopacket.LayerType

			_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)

			for _, layerType := range foundLayerTypes {
				if layerType == layers.LayerTypeTCP {
					if b.tcpLayer.SYN && b.tcpLayer.ACK {
						log.Println("SYN + ACK")
					}
					ok := b.retransmits[b.tcpLayer.Seq]
					if ok {
						log.Println("RETRANSMIT")
						p.Err++
					}
				}
			}

			if newRemotePacket {
				p.Start = time.Now()
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
						Normal: 1,
						Danger: 0,
					},
				}

				vn.Connections = append(vn.Connections, newConnection)
				b.pack.packetSources = append(b.pack.packetSources, srcDst)

				log.Println("Added node")
				ch <- *vn
			}

			p.End = time.Now()
			res.PacketTimeMap[srcDst] = p
		}
	}
}

func getSimpleHostname() string {
	h, err := os.Hostname()
	if err == nil {
		return h
	}

	return "local"
}