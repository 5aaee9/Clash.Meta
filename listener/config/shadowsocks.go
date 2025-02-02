package config

import (
	"github.com/metacubex/mihomo/listener/sing"

	"encoding/json"
)

type ShadowsocksUser struct {
	Username string
	Password string
}

type ShadowsocksServer struct {
	Enable     bool
	Listen     string
	Password   string
	Cipher     string
	Udp        bool
	MultiUsers []ShadowsocksUser
	MuxOption  sing.MuxOption `yaml:"mux-option" json:"mux-option,omitempty"`
}

func (t ShadowsocksServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
