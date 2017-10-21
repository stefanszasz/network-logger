package main

type (
	PacketEntry struct {
		SourceIp, SourcePort           string
		DestinationIP, DestinationPort string
	}

	OutputFormatter interface {
		Header(ips []string) string
		Entry(row *PacketEntry) string
		Footer() string
	}
)

