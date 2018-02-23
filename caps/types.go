package caps

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ec2"
	"log"
	"sync"
)

const (
	internet     = "INTERNET"
	focusedChild = "focusedChild"
	normal       = "normal"
	region       = "region"
	name         = "name"
)

type (
	PacketEntry struct {
		SourceIp, SourcePort           string
		DestinationIP, DestinationPort string
	}

	OutputFormatter interface {
		Header(ips []string) string
		Entry(row *PacketEntry) string
		Footer() string
	}

	Capturer interface {
		StartCapture(in chan VizceralNode) (interface{}, error)
	}

	packetHolder struct {
		packetSources []string
		sync.Mutex
	}

	VizceralNode struct {
		Renderer    string               `json:"renderer"`
		Name        string               `json:"name"`
		Class       string               `json:"class"`
		MaxVolume   int                  `json:"maxVolume"`
		Connections []VizceralConnection `json:"connections"`
		Nodes       []VizceralNode       `json:"nodes"`
	}

	VizceralConnection struct {
		Source  string           `json:"source"`
		Target  string           `json:"target"`
		Class   string           `json:"class"`
		Metrics *VizceralMetric  `json:"metrics"`
		Notices []VizceralNotice `json:"notices"`
		Hash    string
	}

	VizceralMetric struct {
		Normal float64 `json:"normal"`
		Danger float64 `json:"danger"`
	}

	VizceralNotice struct {
		Title    string `json:"title"`
		Link     string `json:"link"`
		Severity int    `json:"severity"`
	}

	instanceCacheHolder struct {
		cache map[string]string
		sync.Mutex
	}

	instancesFoundCacheHolder struct {
		cache EC2Instances
		sync.Mutex
	}

	EC2Instance struct {
		InstanceId, Name, VpcId, Region string
		Enis                            []string
	}

	VPCFlowLogCapInput struct {
		InstanceIds string
	}

	VPCFlowLogCap struct {
		ec2Svc        *ec2.EC2
		InstanceIds   string
		cloudWatchSvc *cloudwatchlogs.CloudWatchLogs
		Region        string
		iCache        instancesFoundCacheHolder
	}
)
type EC2Instances []EC2Instance

func (self VizceralNode) String() string {
	marshal, err := json.Marshal(self)
	if err != nil {
		log.Fatal(err)
	}
	return string(marshal)
}

func (src EC2Instance) String() string {
	if src.Name == "" {
		return src.InstanceId
	}

	return src.Name
}

func (src EC2Instances) findBy(f func(in EC2Instance) bool) *EC2Instance {
	for _, inst := range src {
		res := f(inst)
		if res {
			return &inst
		}
	}

	return nil
}

func MakeRootVizceralNode(root string) *VizceralNode {
	return &VizceralNode{
		Renderer: "global",
		Name:     "edge",
		Nodes: []VizceralNode{
			{
				Class:    normal,
				Renderer: region,
				Name:     internet,
			},
			{
				Class:     normal,
				Renderer:  region,
				Name:      root,
				MaxVolume: 50000,
			},
		},
		Connections: []VizceralConnection{
			{
				Source: internet,
				Target: root,
				Class:  "normal",
				Metrics: &VizceralMetric{
					Danger: 60,
					Normal: 26009,
				},
			},
		},
	}
}
