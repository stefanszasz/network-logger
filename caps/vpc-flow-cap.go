package caps

import (
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/route53"
)

type instanceCacheHolder struct {
	cache map[string]string
	sync.Mutex
}

var instanceCache instanceCacheHolder

type VPCFlowLogCap struct {
	ec2Svc        *ec2.EC2
	InstanceId    string
	cloudWatchSvc *cloudwatchlogs.CloudWatchLogs
	AWSProfile    string
	Region        string
}

type VPCFlowLogCapInput struct {
	AWSProfile string
	InstanceId string
	Region     string
}

func MakeNewVPCFlowCap(in VPCFlowLogCapInput) *VPCFlowLogCap {
	if in.InstanceId == "" {
		panic("InstanceId must be set")
	}

	cfg := &aws.Config{
		Region:      aws.String(in.Region),
		Credentials: credentials.NewSharedCredentials("", in.AWSProfile),
	}
	sess, err := session.NewSession(cfg)
	if err != nil {
		log.Panic(err)
	}

	instanceCache = instanceCacheHolder{cache: make(map[string]string)}

	mappings := os.Getenv("KNOWN_IP_MAPPINGS")
	if mappings != "" {
		tokens := strings.Split(mappings, ";")
		for _, t := range tokens {
			ipName := strings.Split(t, "=")
			instanceCache.Lock()
			instanceCache.cache[ipName[0]] = ipName[1]
			instanceCache.Unlock()
		}
	}

	log.Println("Finished reading DNS entries")

	cwLogs := cloudwatchlogs.New(sess, cfg)

	return &VPCFlowLogCap{cloudWatchSvc: cwLogs, InstanceId: in.InstanceId, AWSProfile: in.AWSProfile, Region: in.Region}
}

func (src VPCFlowLogCap) StartCapture() (*VizceralNode, error) {
	var vpcId, targetedInstanceName string
	var netIfaces, ips []string
	regions := strings.Split(os.Getenv("REGIONS"), ",")

	var wg sync.WaitGroup
	wg.Add(len(regions) + 1)

	go src.fillDNSInstanceCache(&wg)

	log.Println("Starting reading instances...")
	for _, r := range regions {
		go func(region string) {
			defer wg.Done()

			ec2Svc := buildNewEc2Session(region, src.AWSProfile)
			instances, err := ec2Svc.DescribeInstances(&ec2.DescribeInstancesInput{})
			if err != nil {
				log.Panic(err)
			}

			for _, res := range instances.Reservations {
				for _, inst := range res.Instances {
					ip := *inst.PrivateIpAddress
					nameTag := ""
					for _, t := range inst.Tags {
						if strings.ToLower(*t.Key) == name {
							nameTag = *t.Value
							instanceCache.Lock()
							instanceCache.cache[ip] = *t.Value
							instanceCache.Unlock()
						}
					}

					if *inst.InstanceId == src.InstanceId {
						vpcId = *inst.VpcId
						for _, eni := range inst.NetworkInterfaces {
							netIfaces = append(netIfaces, *eni.NetworkInterfaceId)
							ips = append(ips, *eni.PrivateIpAddress)
						}

						if nameTag != "" {
							targetedInstanceName = nameTag
						} else {
							targetedInstanceName = *inst.NetworkInterfaces[0].PrivateIpAddress
						}
					}
				}
			}
		}(r)
	}

	wg.Wait()

	log.Println("Got instances")

	if len(netIfaces) == 0 || len(ips) == 0 {
		panic("Cannot find enis for instance. Can't happen.")
	}

	log.Printf("Found instance "+src.InstanceId+" in VPC "+vpcId+". ENIs: %v. IPs: %v\n", netIfaces, ips)

	f := &ec2.Filter{
		Name:   aws.String("resource-id"),
		Values: []*string{&vpcId},
	}

	ec2Svc := buildNewEc2Session(src.Region, src.AWSProfile)
	fl, err := ec2Svc.DescribeFlowLogs(&ec2.DescribeFlowLogsInput{Filter: []*ec2.Filter{f}})
	if len(fl.FlowLogs) == 0 {
		log.Println("Cannot find flowlogs")
		return nil, errors.New("cannot find flow logs")
	}

	groupName := fl.FlowLogs[0].LogGroupName
	logStreams, _ := src.cloudWatchSvc.DescribeLogStreams(&cloudwatchlogs.DescribeLogStreamsInput{LogGroupName: groupName})
	if len(logStreams.LogStreams) == 0 {
		log.Println("Cannot find log streams at all")
		return nil, errors.New("cannot find log streams at all")
	}

	logStream := netIfaces[0] + "-all"
	gIn := &cloudwatchlogs.GetLogEventsInput{
		LogGroupName:  groupName,
		LogStreamName: &logStream,
	}

	log.Println("Fetching logs...")

	events, err := src.cloudWatchSvc.GetLogEvents(gIn)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	log.Println("Node name: " + targetedInstanceName)

	resultCache := make(map[string]bool)

	rootNode := MakeRootVizceralNode(targetedInstanceName)
	vn := &rootNode.Nodes[1]

	for _, evt := range events.Events {
		tokens := strings.Split(*evt.Message, " ")
		srcIp := tokens[3]
		dstIp := tokens[4]
		action := tokens[12]
		packets := tokens[8]

		srcIsPrivateIp, _ := privateIP(srcIp)
		dstIsPrivateIp, _ := privateIP(dstIp)

		valSrc := getInstanceName(srcIp)
		valDst := getInstanceName(dstIp)

		value := "Src: " + valSrc + ". Destination: " + valDst
		vTokens := strings.Split(value, "")
		sort.Strings(vTokens)
		mapHash := strings.Join(vTokens, "")

		_, ok := resultCache[mapHash]
		if !ok {
			resultCache[mapHash] = true
			fmt.Println(value)

			var internetNode *VizceralNode
			for _, n := range vn.Nodes {
				if n.Name == internet {
					internetNode = &n
				}
			}

			srcIsPublic := !srcIsPrivateIp
			if srcIsPublic {
				valSrc = internet
			}

			dstIsPublic := !dstIsPrivateIp
			if dstIsPublic {
				valDst = internet
			}

			isPublicTraffic := srcIsPublic || dstIsPublic
			if internetNode != nil && isPublicTraffic {
				var con *VizceralConnection
				normalVals, errVals := buildMetrics(packets, action)

				if len(internetNode.Connections) == 0 {
					con = &VizceralConnection{
						Source: valSrc,
						Target: valDst,
						Class:  normal,
						Hash:   mapHash,
						Metrics: &VizceralMetric{
							Normal: math.Min(1000, float64(normalVals)),
							Danger: math.Min(1000, float64(errVals)),
						},
					}
				} else {
					con = &internetNode.Connections[0]

					con.Metrics.Normal = math.Min(1000, con.Metrics.Normal+float64(normalVals))
					con.Metrics.Danger = math.Min(1000, con.Metrics.Danger+float64(errVals))
				}

				vn.Connections = append(vn.Connections, *con)

				continue
			}

			srcNode := VizceralNode{
				Name:     valSrc,
				Renderer: focusedChild,
				Class:    normal,
			}

			dstNode := VizceralNode{
				Name:     valDst,
				Renderer: focusedChild,
				Class:    normal,
			}

			vn.Nodes = append(vn.Nodes, srcNode, dstNode)

			normalVals, errVals := buildMetrics(packets, action)

			newConnection := VizceralConnection{
				Source: srcNode.Name,
				Target: dstNode.Name,
				Class:  normal,
				Hash:   mapHash,
				Metrics: &VizceralMetric{
					Normal: float64(normalVals),
					Danger: float64(errVals),
				},
			}

			if srcNode.Name == srcIp || dstNode.Name == dstIp {
				not := VizceralNotice{
					Link:     "https://some.link",
					Severity: 1,
					Title:    "instance missing?",
				}
				newConnection.Notices = append(newConnection.Notices, not)
			}
			vn.Connections = append(vn.Connections, newConnection)
		} else {
			for _, con := range vn.Connections {
				if con.Hash == mapHash {
					normalVals, errVals := buildMetrics(packets, action)
					newNorm := con.Metrics.Normal + float64(normalVals)
					newErr := con.Metrics.Danger + float64(errVals)

					con.Metrics.Normal = math.Min(1000, newNorm)
					con.Metrics.Danger = math.Min(1000, newErr)
				}
			}
		}
	}

	return rootNode, nil
}

func (src VPCFlowLogCap) fillDNSInstanceCache(wg *sync.WaitGroup) {
	log.Println("Reading DNS entries")
	defer wg.Done()

	cfg, sess := buildNewAwsConfigSession(src.Region, src.AWSProfile)
	r53 := route53.New(sess, cfg)

	zones, _ := r53.ListHostedZones(&route53.ListHostedZonesInput{})
	for _, z := range zones.HostedZones {
		in := &route53.ListResourceRecordSetsInput{HostedZoneId: z.Id}
		rs, _ := r53.ListResourceRecordSets(in)

		for _, r := range rs.ResourceRecordSets {
			if *r.Type == "A" {
				if len(r.ResourceRecords) > 0 {
					ipVal := strings.TrimSpace(*r.ResourceRecords[0].Value)
					dName := strings.TrimRight(*r.Name, ".")
					instanceCache.Lock()
					instanceCache.cache[ipVal] = dName
					instanceCache.Unlock()
				}
			}
		}
	}

	log.Println("Finished reading DNS entires")
}

func getInstanceName(instanceId string) string {
	name, found := instanceCache.cache[instanceId]
	if !found {
		return instanceId
	}

	return name
}

func buildNewEc2Session(region string, profile string) *ec2.EC2 {
	cfg, sess := buildNewAwsConfigSession(region, profile)
	return ec2.New(sess, cfg)
}

func buildNewAwsConfigSession(region string, profile string) (*aws.Config, *session.Session) {
	cfg := &aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewSharedCredentials("", profile),
	}
	sess, err := session.NewSession(cfg)
	if err != nil {
		log.Panic(err)
	}

	return cfg, sess
}

func privateIP(ip string) (bool, error) {
	var err error
	private := false
	IP := net.ParseIP(ip)
	if IP == nil {
		err = errors.New("invalid IP")
	} else {
		_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
		_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
		_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
		private = private24BitBlock.Contains(IP) || private20BitBlock.Contains(IP) || private16BitBlock.Contains(IP)
	}
	return private, err
}

func buildMetrics(packets string, action string) (int, int) {
	normal, _ := strconv.Atoi(packets)
	errors := 0

	if action == "REJECT" {
		errors = normal
		normal = 0
	}

	return normal, errors
}
