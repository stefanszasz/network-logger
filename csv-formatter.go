package main

import (
	"fmt"
	"stefanszasz/network-logger/caps"
)

type CsvFormatter struct{}

func (formatter CsvFormatter) Header(ips []string) string {
	return ""
}

func (formatter CsvFormatter) Footer() string {
	return ""
}

func (formatter CsvFormatter) Entry(row *caps.PacketEntry) string {
	srcIp := row.SourceIp
	dstIp := row.DestinationIP

	return fmt.Sprintf("%v, %v\n", srcIp, dstIp)
}
