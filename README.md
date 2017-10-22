# Network logger
Simple network traffic capture utility that relies on gopacket/libpcap.

## Goal
Create [Vizceral](https://github.com/Netflix/vizceral "Vizceral") network traffic visualizations using [BPF filters](http://biot.com/capstats/bpf.html). 

## Usage
Run: `go build` in the current directory, then execute the program using a BPF as a first argument - it will ask for `sudo` privileges.
For example: start `sudo --filter="tcp port 443"
                         --out="/Users/myuser/generated.json"
                         --dev=en0`; you can use `Ctrl + C` to stop after few seconds which will cause the `generated.json` file to be created or overwritten.


<img src="https://raw.githubusercontent.com/stefanszasz/network-logger/master/assets/vizceral-1.png" width="300" />