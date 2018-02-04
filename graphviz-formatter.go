package main

import (
	"fmt"
	"stefanszasz/network-logger/caps"
)

type GraphVizFormatter struct{}

func (formatter GraphVizFormatter) Header(ips []string) string {
	header := "node [shape = doublecircle]; "
	for _, addr := range ips {
		header += fmt.Sprintf("\"%v\";", addr)
	}
	header += "\n"

	fmt.Printf("digraph interface_capture { \n\t rankdir=LR; \n\t size=\"10\" \n\t %v \"%v\"; \n\t node [shape = circle]; \n", header, ips[0])

	return header
}

func (formatter GraphVizFormatter) Footer() string {
	return "}\n"
}

func (formatter GraphVizFormatter) Entry(row *caps.PacketEntry) string {
	srcIp := row.SourceIp
	dstIp := row.DestinationIP

	return fmt.Sprintf("\t \"%v\" -> \"%v\" [ label = \"%v\" ];\n", srcIp, dstIp, row.DestinationPort)
}
