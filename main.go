package main

import (
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"io/ioutil"
	"os/exec"

	"flag"

	"fmt"
	"stefanszasz/network-logger/caps"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

var (
	localIp, bpfFilter, outputFile string
	awsProfile, instanceId         string
	devName, hostName, fileOwner   string
	capRes                         caps.BPFCaptureResult
	ch                             chan caps.VizceralNode
)

func init() {
	flag.StringVar(&bpfFilter, "filter", "tcp", "filter=\"tcp and udp\"")
	flag.StringVar(&outputFile, "out", "/tmp/generated.json", "out=/path/to/file.json")
	flag.StringVar(&devName, "dev", "", "dev=en0")
	flag.StringVar(&fileOwner, "fileowner", "", "fileowner=username")

	flag.StringVar(&awsProfile, "profile", "", "profile=awsprofile")
	flag.StringVar(&instanceId, "instanceId", "", "instanceId=i-182716171")

	flag.Parse()

	if fileOwner == "" {
		log.Fatal("--fileowner argument must be set")
	}
}

func main() {
	//handleTermination()

	//in := &caps.BPFCaptureInput{Device: devName, Filter: bpfFilter}
	//bpfCap := caps.MakeNewBPFCapture(in)

	//ch := make(chan caps.VizceralNode)
	//_, err := bpfCap.StartCapture(ch)
	//if err != nil {
	//	log.Panic(err)
	//}

	in := caps.VPCFlowLogCapInput{AWSProfile: awsProfile, InstanceId: instanceId}
	c := caps.MakeNewVPCFlowCap(in)
	r, _ := c.StartCapture()
	trySavingOutput(r.String())
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
				con.Metrics.Danger = float64(timeSlice.Err)
				log.Printf("Packets / sec: %.2f", packPerSec)
			}
		}

		jsonResult := vn.String()
		log.Println(jsonResult)

		trySavingOutput(jsonResult)
		os.Exit(0)
	}()
}

func trySavingOutput(jsonResult string) {
	if outputFile != "" {
		fmt.Println("Saving output...")
		if strings.Contains(outputFile, "s3://") {
			cfg := &aws.Config{Credentials: credentials.NewSharedCredentials("", awsProfile)}
			sess, err := session.NewSession(cfg)
			if err != nil {
				log.Panic(err)
			}

			bucketName := os.Getenv("OUT_BUCKET")
			if bucketName == "" {
				log.Println("Cannot find which bucket to write to. Exiting")
				return
			}
			s3client := s3.New(sess, cfg)
			file := instanceId + "-" + time.Now().UTC().String() + ".json"
			_, err = s3client.CopyObject(&s3.CopyObjectInput{Bucket: &bucketName, Key: &file})
			if err != nil {
				log.Println("Cannot copy file to s3: ", err.Error())
			}
		} else {
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
}
