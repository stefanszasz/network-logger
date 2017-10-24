package main

import (
	"encoding/json"
	"log"
)

type (
	VizceralNode struct {
		Renderer    string               `json:"renderer"`
		Name        string               `json:"name"`
		Class       string               `json:"class"`
		MaxVolume   int                  `json:"maxVolume"`
		Connections []VizceralConnection `json:"connections"`
		Nodes       []VizceralNode       `json:"nodes"`
	}

	VizceralConnection struct {
		Source  string          `json:"source"`
		Target  string          `json:"target"`
		Class   string          `json:"class"`
		Metrics *VizceralMetric `json:"metrics"`
	}

	VizceralMetric struct {
		Normal float64 `json:"normal"`
		Danger int     `json:"danger"`
	}
)

func (self VizceralNode) String() string {
	marshal, err := json.Marshal(self)
	if err != nil {
		log.Fatal(err)
	}
	return string(marshal)
}

func MakeRootVizceralNode(root string) VizceralNode {
	return VizceralNode{
		Renderer: "global",
		Name:     "edge",
		Nodes: []VizceralNode{
			{
				Class:    normal,
				Renderer: region,
				Name:     internet,
			},
			{
				Class:     normal,
				Renderer:  region,
				Name:      root,
				MaxVolume: 50000,
			},
		},
		Connections: []VizceralConnection{
			{
				Source: internet,
				Target: root,
				Class:  "normal",
				Metrics: &VizceralMetric{
					Danger: 60,
					Normal: 26009,
				},
			},
		},
	}
}
