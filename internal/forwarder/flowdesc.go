package forwarder

import (
	"github.com/free5gc/go-upf/internal/rules"
	"net"
)

// These wrappers retain the legacy builder API during the typed-rule migration.
type FlowDesc = rules.FlowDesc

func ParseFlowDesc(s string) (*FlowDesc, error)       { return rules.ParseFlowDesc(s) }
func ParseFlowDescIPNet(s string) (*net.IPNet, error) { return rules.ParseFlowDescIPNet(s) }
func ParseFlowDescPorts(s string) ([][]uint16, error) { return rules.ParseFlowDescPorts(s) }
