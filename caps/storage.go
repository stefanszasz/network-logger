package caps

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

type StoreInput struct {
	FileName, FileOwner, Content, Title string
}

type Storer interface {
	Store()
}

type FileStorer struct {
	StoreInput
}

type S3Storer struct {
	StoreInput
}

func (f FileStorer) Store() {
	err := ioutil.WriteFile(f.FileName, []byte(f.Content), 0666)
	if err != nil {
		log.Fatal("Cannot save file: ", err)
	}
	cmd := exec.Command("chown", f.FileOwner, f.FileName)
	_, err = cmd.Output()
	if err != nil {
		log.Fatal("Cannot change owner: " + err.Error())
	}
	log.Println("Saved to: " + f.FileName)
}


func (s S3Storer) Store() {
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
	file := s.FileName + "-" + time.Now().UTC().String() + ".json"
	_, err = s3client.CopyObject(&s3.CopyObjectInput{Bucket: &bucketName, Key: &file})
	if err != nil {
		log.Println("Cannot copy file to s3: ", err.Error())
	}
}

func MakeNewStorer(in StoreInput) Storer {
	if strings.Index(strings.ToLower(in.FileName), "s3://") > -1 {
		return S3Storer{in}
	}

	return FileStorer{in}
}
