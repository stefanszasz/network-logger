package caps

type VPCFlowLogCap struct {
}

func (src VPCFlowLogCap) StartCapture() string {
	return ""
}

type VPCFlowLogCapInput struct {
	AWSProfile string
	InstanceId string
}

func MakeNewVPCFlowCap(in VPCFlowLogCapInput) *VPCFlowLogCap {
	return &VPCFlowLogCap{}
}
