package main

type PacketEntry struct {
	SourceIp, SourcePort           string
	DestinationIP, DestinationPort string
}

type OutputFormatter interface {
	Header(ips []string) string
	Entry(row *PacketEntry) string
	Footer() string
}
