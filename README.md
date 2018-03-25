# Network logger
Simple network traffic capture utility that relies on gopacket/libpcap and AWS Flow Logs to visualize network
traffic.

## Goal
Create [Vizceral](https://github.com/Netflix/vizceral "Vizceral") network traffic visualizations using [BPF filters](http://biot.com/capstats/bpf.html) 
and [AWS VPC Flow Logs](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html). The tool build a JSON model 
that is read by Vizceral to visualize traffic.

## Usage

The program's VPC FlowLogs exporter works only if the targeted instances' VPC have flow logs enabled and the logs are in CloudWatch Logs  

Run: `go build` in the current directory, then run it using the parameter and environment variables configuration:

* params: `./network-logger --fileowner=OWNER
                    --out=.....vizceral-example/dist/generated.json`. This will case the `generated.json` file 
                    to be exported in the location specified by the parameter

* environment variables:
    - SOURCE: `vpc-flowlog` or `bpf-filter` - bpf-filter implementation is in progress
    - AWS_REGIONS: comma separated AWS region values to fetch VPC flow logs from
    - INSTANCE_IDS: comma separated EC2 instance IDs
    - AWS_REGION: sdk region
    - AWS_PROFILE: sdk profile 


<img src="https://raw.githubusercontent.com/stefanszasz/network-logger/master/assets/vizceral-1.png" width="500" />

## Notes

1. BPF exporter is in progress
2. No tests