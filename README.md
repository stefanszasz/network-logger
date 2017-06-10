# Network logger
Simple network traffic capture utility that relies on gopacket/libpcap.

## Goal
Create [Graphviz](http://www.graphviz.org "Graphviz") network traffic visualizations using [BPF filters](http://biot.com/capstats/bpf.html). 

## Usage
Run: `go build` in the current directory, then execute the program using a BPF as a first argument. 
For example: start `sudo ./network-logger "tcp and udp" > output.data`. This will start to capture tcp & udp traffic and will output this to a file using graphviz *dot*-syntax based output that you can use to visualise network traffic using Graphviz tools.

Output should look like this:

`digraph interface_capture { 
 	 rankdir=LR; 
 	 size="8";
 	 node [shape = doublecircle]; "192.168.1.12"; 
 	 node [shape = circle]; 
 	 "173.194.68.108" -> "192.168.1.12" [ label = "53084" ];
 	 "192.168.1.12" -> "173.194.68.108" [ label = "993(imaps)" ];
 	 "192.168.1.12" -> "52.216.18.3" [ label = "443(https)" ];
 	 "51.58.224.81" -> "192.168.1.12" [ label = "53081" ];
 	 "192.168.1.12" -> "51.58.224.81" [ label = "443(https)" ];
 	 "192.168.1.12" -> "51.58.210.95" [ label = "443(https)" ];
 	 "192.168.1.12" -> "51.58.208.110" [ label = "443(https)" ];
 	 "192.168.1.12" -> "34.194.186.234" [ label = "443(https)" ];
 }
`

Having this output, one can visualize the graph using local or remote graphviz tools such as [Webgraphviz](http://www.webgraphviz.com/ "Webgraphviz") - on this page, you can paste the contents of your output and click *Generate Graph!*:

<img src="https://raw.githubusercontent.com/stefanszasz/network-logger/master/network-log-1.png" width="300" />