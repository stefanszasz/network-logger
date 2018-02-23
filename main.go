package main

import (
	"log"
	"os"
	"strings"
	"time"

	"io/ioutil"
	"os/exec"

	"flag"

	"stefanszasz/network-logger/caps"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
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
			trySavingOutput(n.String())
		}
	}
}

func trySavingOutput(jsonResult string) {
	if outputFile != "" {
		log.Println("Saving output...")
		if strings.Contains(outputFile, "s3://") {
			cfg := &aws.Config{}
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
			file := instanceIds + "-" + time.Now().UTC().String() + ".json"
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
			log.Println("Saved to: " + outputFile)
		}
	}
}
