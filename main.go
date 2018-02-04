package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"io/ioutil"
	"os/exec"

	"flag"

	"fmt"
	"stefanszasz/network-logger/caps"
)

var (
	localIp, bpfFilter, outputFile string
	devName, hostName, fileOwner   string
	capRes                         caps.BPFCaptureResult
	ch                             chan caps.VizceralNode
)

func init() {
	flag.StringVar(&bpfFilter, "filter", "tcp", "filter=\"tcp and udp\"")
	flag.StringVar(&outputFile, "out", "/tmp/generated.json", "out=/path/to/file.json")
	flag.StringVar(&devName, "dev", "", "dev=en0")
	flag.StringVar(&fileOwner, "fileowner", "", "fileowner=username")

	flag.Parse()

	if fileOwner == "" {
		log.Fatal("--fileowner argument must be set")
	}
}

func main() {
	handleTermination()

	in := &caps.BPFCaptureInput{Device: devName, Filter: bpfFilter}
	bpfCap := caps.MakeNewBPFCapture(in)

	ch := make(chan caps.VizceralNode)
	_, err := bpfCap.StartCapture(ch)
	if err != nil {
		log.Panic(err)
	}
}

func handleTermination() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		<-c
		vn := <-ch
		vn.Nodes[1].Name = hostName

		connections := vn.Nodes[1].Connections

		for _, con := range connections {
			conKey := con.Source + con.Target
			timeSlice := capRes.PacketTimeMap[conKey]
			if timeSlice.Count > 1 {
				timeFrames := capRes.PacketTimeMap[conKey]
				secondsDiff := timeFrames.End.Sub(timeFrames.Start).Seconds()

				packPerSec := float64(timeFrames.Count) / secondsDiff
				con.Metrics.Normal = packPerSec
				con.Metrics.Danger = timeSlice.Err
				log.Printf("Packets / sec: %.2f", packPerSec)
			}
		}

		jsonResult := vn.String()
		log.Println(jsonResult)

		trySavingToFile(jsonResult)
		os.Exit(0)
	}()
}

func trySavingToFile(jsonResult string) {
	if outputFile != "" {
		fmt.Println("Saving to file")
		err := ioutil.WriteFile(outputFile, []byte(jsonResult), 0666)
		if err != nil {
			log.Fatal("Cannot save file: ", err)
		}
		cmd := exec.Command("chown", fileOwner, outputFile)
		_, err = cmd.Output()
		if err != nil {
			log.Fatal("Cannot change owner: " + err.Error())
		}
		fmt.Println("Saved to: " + outputFile)
	}
}
