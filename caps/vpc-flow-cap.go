package caps

import (
	"errors"
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/route53"
)

var instanceIPNameCache instanceCacheHolder

func MakeNewVPCFlowCap(in VPCFlowLogCapInput) *VPCFlowLogCap {
	if in.InstanceIds == "" {
		panic("InstanceId must be set")
	}

	cfg := &aws.Config{}
	sess, err := session.NewSession(cfg)
	if err != nil {
		log.Panic(err)
	}

	instanceIPNameCache = instanceCacheHolder{cache: make(map[string]string)}

	mappings := os.Getenv("KNOWN_IP_MAPPINGS")
	if mappings != "" {
		tokens := strings.Split(mappings, ";")
		for _, t := range tokens {
			ipName := strings.Split(t, "=")
			instanceIPNameCache.cache[ipName[0]] = ipName[1]
		}
	}

	log.Println("Finished reading DNS entries")

	cwLogs := cloudwatchlogs.New(sess, cfg)

	return &VPCFlowLogCap{cloudWatchSvc: cwLogs, InstanceIds: in.InstanceIds}
}

func (src VPCFlowLogCap) StartCapture() ([]*VizceralNode, error) {
	instanceIdNameMap := make(map[string]string)
	instanceTokens := strings.Split(src.InstanceIds, ",")
	for _, tokens := range instanceTokens {
		instanceIdNameMap[tokens] = ""
	}

	var wg sync.WaitGroup
	go src.fillDNSInstanceCache(&wg)
	src.fillInstanceCache(&wg)

	var foundInstances EC2Instances
	for _, instId := range instanceTokens {
		locInst := src.findInstanceFromCache(func(in EC2Instance) bool {
			return in.InstanceId == instId
		})
		if locInst == nil || locInst.InstanceId == "" {
			log.Printf("Counldn't find instance %s. Skipping. \n", instId)
			continue
		}
		foundInstances = append(foundInstances, *locInst)
	}

	if len(foundInstances) == 0 {
		return nil, errors.New("couldn't find any instances. Exiting")
	}

	var rootNodes []*VizceralNode

	for _, instance := range foundInstances {
		gIn, err := src.buildFlowLogInput(&instance)
		if err != nil {
			log.Println(err.Error())
			continue
		}

		log.Println("Fetching logs...")
		eventResponse, err := src.cloudWatchSvc.GetLogEvents(gIn)
		if err != nil {
			log.Println(err)
			return nil, err
		}

		node := src.buildGraph(&instance, eventResponse.Events)
		rootNodes = append(rootNodes, node)
	}

	return rootNodes, nil
}

func (src *VPCFlowLogCap) fillDNSInstanceCache(wg *sync.WaitGroup) {
	log.Println("Reading DNS entries")
	wg.Add(1)
	defer wg.Done()

	cfg, session := buildNewAwsConfigSession("")
	r53 := route53.New(session, cfg)

	zones, _ := r53.ListHostedZones(&route53.ListHostedZonesInput{})
	for _, z := range zones.HostedZones {
		in := &route53.ListResourceRecordSetsInput{HostedZoneId: z.Id}
		rs, _ := r53.ListResourceRecordSets(in)

		for _, r := range rs.ResourceRecordSets {
			if *r.Type == "A" {
				if len(r.ResourceRecords) > 0 {
					ipVal := strings.TrimSpace(*r.ResourceRecords[0].Value)
					dName := strings.TrimRight(*r.Name, ".")
					instanceIPNameCache.Lock()
					instanceIPNameCache.cache[ipVal] = dName
					instanceIPNameCache.Unlock()
				}
			}
		}
	}

	log.Println("Finished reading DNS entires")
}

func (src *VPCFlowLogCap) buildGraph(instance *EC2Instance, events []*cloudwatchlogs.OutputLogEvent) *VizceralNode {
	sourceDestCache := make(map[string]bool)

	rootNode := MakeRootVizceralNode(instance.String())
	vn := &rootNode.Nodes[1]

	for _, evt := range events {
		tokens := strings.Split(*evt.Message, " ")
		srcIP := tokens[3]
		dstIP := tokens[4]
		action := tokens[12]
		packets := tokens[8]

		srcIsPrivateIP, _ := privateIP(srcIP)
		dstIsPrivateIP, _ := privateIP(dstIP)

		valSrc := src.getInstanceName(srcIP)
		valDst := src.getInstanceName(dstIP)

		value := "Src: " + valSrc + ". Destination: " + valDst
		vTokens := strings.Split(value, "")
		sort.Strings(vTokens)
		mapHash := strings.Join(vTokens, "")

		_, ok := sourceDestCache[mapHash]
		if !ok {
			//startDateStr := tokens[10]
			endDateStr := tokens[11]
			//sD, _ := strconv.Atoi(startDateStr)
			eD, _ := strconv.Atoi(endDateStr)
			//startDate := time.Unix(int64(sD), 0)
			//log.Printf("%v", startDate)
			endDate := time.Unix(int64(eD), 0)
			sourceDestCache[mapHash] = true
			//fmt.Println(value)

			if endDate.UTC().Day() != time.Now().UTC().Day() {
				log.Println("Not today - skip")
			}

			var internetNode *VizceralNode
			for _, n := range vn.Nodes {
				if n.Name == internet {
					internetNode = &n
				}
			}

			srcIsPublic, dstIsPublic := !srcIsPrivateIP, !dstIsPrivateIP
			if srcIsPublic {
				valSrc = internet
			}

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

			//if srcNode.Name == srcIp || dstNode.Name == dstIp {
			//	not := VizceralNotice{
			//		Link:     "https://some.link",
			//		Severity: 1,
			//		Title:    "instance missing?",
			//	}
			//	newConnection.Notices = append(newConnection.Notices, not)
			//}
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

	return rootNode
}

func (src *VPCFlowLogCap) fillInstanceCache(wg *sync.WaitGroup) {
	regions := strings.Split(os.Getenv("REGIONS"), ",")

	wg.Add(len(regions))

	for _, r := range regions {
		go func(region string) {
			defer wg.Done()

			ec2Svc := buildNewEc2Session(region)
			instances, err := ec2Svc.DescribeInstances(&ec2.DescribeInstancesInput{})
			if err != nil {
				log.Panic(err)
			}

			for _, res := range instances.Reservations {
				for _, inst := range res.Instances {
					ip := *inst.PrivateIpAddress
					nameTag := ""

					instance := EC2Instance{
						InstanceId: *inst.InstanceId,
						VpcId:      *inst.VpcId,
					}

					for _, t := range inst.Tags {
						if strings.ToLower(*t.Key) == name {
							nameTag = *t.Value
							instance.Name = nameTag
							instanceIPNameCache.Lock()
							instanceIPNameCache.cache[ip] = *t.Value
							instanceIPNameCache.Unlock()
						}
					}

					az := *inst.Placement.AvailabilityZone
					inRegion := az[0 : len(az)-1]
					instance.Region = inRegion

					for _, eni := range inst.NetworkInterfaces {
						instance.Enis = append(instance.Enis, *eni.NetworkInterfaceId)
					}

					src.iCache.Lock()
					src.iCache.cache = append(src.iCache.cache, instance)
					src.iCache.Unlock()
				}
			}
		}(r)
	}

	wg.Wait()

	log.Printf("Found %d instances in ec2", +len(src.iCache.cache))
}

func (src *VPCFlowLogCap) buildFlowLogInput(instance *EC2Instance) (*cloudwatchlogs.GetLogEventsInput, error) {
	f := &ec2.Filter{
		Name:   aws.String("resource-id"),
		Values: []*string{&instance.VpcId},
	}

	ec2Svc := buildNewEc2Session(instance.Region)
	fl, err := ec2Svc.DescribeFlowLogs(&ec2.DescribeFlowLogsInput{Filter: []*ec2.Filter{f}})
	if err != nil {
		log.Printf("%v\n", err)
	}
	if len(fl.FlowLogs) == 0 {
		return nil, errors.New("cannot find flow logs for instance " + instance.InstanceId + "; name: " + instance.Name)
	}

	groupName := fl.FlowLogs[0].LogGroupName
	logStreams, err := src.cloudWatchSvc.DescribeLogStreams(&cloudwatchlogs.DescribeLogStreamsInput{LogGroupName: groupName})
	if err != nil {
		return nil, err
	}
	if len(logStreams.LogStreams) == 0 {
		return nil, errors.New("cannot find log streams at all")
	}

	logStream := instance.Enis[0] + "-all"
	gIn := &cloudwatchlogs.GetLogEventsInput{
		LogGroupName:  groupName,
		LogStreamName: &logStream,
	}
	return gIn, nil
}

func (src *VPCFlowLogCap) getInstanceName(instanceID string) string {
	name, found := instanceIPNameCache.cache[instanceID]
	if !found {
		instance := src.findInstanceFromCache(func(in EC2Instance) bool {
			return in.InstanceId == instanceID
		})
		if instance == nil {
			return instanceID
		}

		return instance.String()
	}

	return name
}

func (src *VPCFlowLogCap) findInstanceFromCache(f func(in EC2Instance) bool) *EC2Instance {
	return src.iCache.cache.findBy(f)
}