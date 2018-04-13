package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"stefanszasz/network-logger/caps"
	"syscall"
)

var (
	localIp, bpfFilter, outputFile            string
	devName, hostName, fileOwner, instanceIds string
	ch                                        chan caps.VizceralNode
)

func init() {
	flag.StringVar(&bpfFilter, "filter", "tcp", "filter=\"tcp and udp\"")
	flag.StringVar(&outputFile, "out", "/tmp/generated.json", "out=/path/to/file.json")
	flag.StringVar(&devName, "dev", "", "dev=en0")
	flag.StringVar(&fileOwner, "fileowner", "", "fileowner=username")
	flag.StringVar(&instanceIds, "instanceIds", os.Getenv("INSTANCE_IDS"), "instanceIds=i-182716171")

	flag.Parse()

	if fileOwner == "" {
		log.Fatal("--fileowner argument must be set")
	}
}

func main() {
	flowSource := os.Getenv("SOURCE")
	if flowSource == "" {
		log.Fatal("SOURCE env var must be set and should be either 'vpc-flowlog' or 'bpf-filter'")
	}

	if flowSource == "vpc-flowlog" {
		in := caps.VPCFlowLogCapInput{InstanceIds: instanceIds}
		capture := caps.MakeNewVPCFlowCap(in)
		nodes, _ := capture.StartCapture()
		log.Printf("Total nodes %d", len(nodes))
		for _, n := range nodes {
			trySavingOutput(n.String(), n.Title(), n.InstanceId)
		}
	} else if flowSource == "bpf-filter" {
		handleTermination()
		in := &caps.BPFCaptureInput{Device: devName, Filter: bpfFilter}
		bpfCap := caps.MakeNewBPFCapture(in)

		ch := make(chan caps.VizceralNode)
		_, err := bpfCap.StartCapture(ch)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Fatal("SOURCE env var must be 'vpc-flowlog' or 'bpf-filter'")
	}
}

func trySavingOutput(jsonResult, title, id string) {
	store := caps.MakeNewStorer(caps.StoreInput{
		FileName:  outputFile,
		FileOwner: fileOwner,
		Content:   jsonResult,
		Title:     title,
		Id:        id,
	})
	store.Store()
}

func handleTermination() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		<-c
		vn := <-ch
		vn.Nodes[1].Name = hostName
		// TODO: handle node finish when closing manually
		//connections := vn.Nodes[1].Connections

		// for _, con := range connections {
		// 	conKey := con.Source + con.Target
		// 	timeSlice := capRes.PacketTimeMap[conKey]
		// 	if timeSlice.Count > 1 {
		// 		timeFrames := capRes.PacketTimeMap[conKey]
		// 		secondsDiff := timeFrames.End.Sub(timeFrames.Start).Seconds()
		//
		// 		packPerSec := float64(timeFrames.Count) / secondsDiff
		// 		con.Metrics.Normal = packPerSec
		// 		con.Metrics.Danger = float64(timeSlice.Err)
		// 		log.Printf("Packets / sec: %.2f", packPerSec)
		// 	}
		// }
		//
		// jsonResult := vn.String()
		// log.Println(jsonResult)
		//
		// trySavingOutput(jsonResult)
		os.Exit(0)
	}()
}
