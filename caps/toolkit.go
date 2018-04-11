package caps

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"log"
	"net"
	"strconv"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/rds"
)

func privateIP(ip string) (bool, error) {
	var err error
	private := false
	IP := net.ParseIP(ip)
	if IP == nil {
		err = errors.New("invalid IP")
		return false, err
	}

	_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
	private = private24BitBlock.Contains(IP) || private20BitBlock.Contains(IP) || private16BitBlock.Contains(IP)
	return private, err
}

func buildMetrics(packets string, action string) (int, int) {
	normal, _ := strconv.Atoi(packets)
	errs := 0

	if action == "REJECT" {
		errs = normal
		normal = 0
	}

	return normal, errs
}

func buildNewEc2Session(region string) *ec2.EC2 {
	cfg, sess := buildNewAwsConfigSession(region)
	ec2Inst := ec2.New(sess, cfg)
	return ec2Inst
}

func buildNewELBSession(region string) *elb.ELB {
	cfg, sess := buildNewAwsConfigSession(region)
	elbSession := elb.New(sess, cfg)
	return elbSession
}

func buildNewECSSession(region string) *ecs.ECS {
	cfg, sess := buildNewAwsConfigSession(region)
	session := ecs.New(sess, cfg)
	return session
}

func buildNewRDSSession(region string) *rds.RDS {
	cfg, sess := buildNewAwsConfigSession(region)
	session := rds.New(sess, cfg)
	return session
}

func buildNewAwsConfigSession(region string) (*aws.Config, *session.Session) {
	cfg := &aws.Config{
		Region: &region,
	}
	sess, err := session.NewSession(cfg)
	if err != nil {
		log.Fatalln(err)
	}

	return cfg, sess
}
