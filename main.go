package main

import (
	"flag"
	"log"
	"os"
	"stefanszasz/network-logger/caps"
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
		log.Panic("SOURCE env var must be set.")
	}

	if flowSource == "vpc-flowlog" {
		in := caps.VPCFlowLogCapInput{InstanceIds: instanceIds}
		capture := caps.MakeNewVPCFlowCap(in)
		nodes, _ := capture.StartCapture()
		for _, n := range nodes {
			trySavingOutput(n.String(), n.Title())
		}
	}
}

func trySavingOutput(jsonResult string, title string) {
	store := caps.MakeNewStorer(caps.StoreInput{
		FileName:  outputFile,
		FileOwner: fileOwner,
		Content:   jsonResult,
		Title:     title,
	})
	store.Store()
}
