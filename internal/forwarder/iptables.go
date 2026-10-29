package forwarder

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
)

type iptablesRule struct {
	table string
	chain string
	args  []string
}

type commandRunner func(name string, args ...string) error

type IptablesManager struct {
	run        commandRunner
	ownedRules []iptablesRule
	mu         sync.Mutex
}

func NewIptablesManager() *IptablesManager {
	return newIptablesManager(runCommand)
}

func newIptablesManager(run commandRunner) *IptablesManager {
	return &IptablesManager{
		run: run,
	}
}

func runCommand(name string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return nil
}

func (m *IptablesManager) AddDNNRules(cidr, ifName, ifCIDR string, ipForwardEnable bool, tcpMSS uint16) error {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("invalid NAT CIDR %q: %w", cidr, err)
	}
	ifName, err := resolveNatIfName(ifName, ifCIDR)
	if err != nil {
		return err
	}

	if err := m.addRule(masqueradeRule(cidr, ifName)); err != nil {
		return fmt.Errorf("install NAT MASQUERADE rule for %s via %s: %w", cidr, ifName, err)
	}
	if !ipForwardEnable {
		return nil
	}
	for _, rule := range ipForwardRules(cidr, ifName) {
		if err := m.addRule(rule); err != nil {
			return fmt.Errorf("install IP forward rule for %s via %s: %w", cidr, ifName, err)
		}
	}
	if err := m.addRule(tcpMSSClampRule(tcpMSS)); err != nil {
		return fmt.Errorf("install TCP MSS clamp rule: %w", err)
	}
	return nil
}

func resolveNatIfName(ifName, ifCIDR string) (string, error) {
	if ifName != "" {
		if _, err := net.InterfaceByName(ifName); err != nil {
			return "", fmt.Errorf(
				"natifname %q not found in current network namespace; "+
					"use an interface visible to the UPF process, or leave natifname empty and set natIfCIDR: %w",
				ifName, err)
		}
		return ifName, nil
	}

	if ifCIDR == "" {
		return "", fmt.Errorf("natifname or natIfCIDR is required to install iptables rules")
	}
	_, targetNet, err := net.ParseCIDR(ifCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid natIfCIDR %q: %w", ifCIDR, err)
	}

	var matches []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list network interfaces: %w", err)
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return "", fmt.Errorf("list addresses for interface %q: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			ip := interfaceAddrIP(addr)
			if ip == nil {
				continue
			}
			if targetNet.Contains(ip) {
				matches = append(matches, iface.Name)
				break
			}
		}
	}

	switch len(matches) {
	case 0:
		return "", fmt.Errorf("natIfCIDR %q did not match any interface in current network namespace", ifCIDR)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf(
			"natIfCIDR %q matched multiple interfaces %s; set natifname explicitly",
			ifCIDR, strings.Join(matches, ", "))
	}
}

func interfaceAddrIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

func (m *IptablesManager) Cleanup() []error {
	m.mu.Lock()
	rules := append([]iptablesRule(nil), m.ownedRules...)
	m.ownedRules = nil
	m.mu.Unlock()

	var errs []error
	for i := len(rules) - 1; i >= 0; i-- {
		rule := rules[i]
		if err := m.run("iptables", rule.commandArgs("-D")...); err != nil {
			errs = append(errs, fmt.Errorf("delete iptables rule %s: %w", strings.Join(rule.commandArgs("-D"), " "), err))
		}
	}
	return errs
}

func (m *IptablesManager) addRule(rule iptablesRule) error {
	if err := m.run("iptables", rule.commandArgs("-C")...); err == nil {
		return nil
	}
	if err := m.run("iptables", rule.commandArgs("-A")...); err != nil {
		return err
	}

	m.mu.Lock()
	m.ownedRules = append(m.ownedRules, rule)
	m.mu.Unlock()
	return nil
}

func (r iptablesRule) commandArgs(op string) []string {
	args := make([]string, 0, len(r.args)+5)
	if r.table != "" {
		args = append(args, "-t", r.table)
	}
	args = append(args, op, r.chain)
	args = append(args, r.args...)
	return args
}

func masqueradeRule(cidr, ifName string) iptablesRule {
	return iptablesRule{
		table: "nat",
		chain: "POSTROUTING",
		args:  []string{"-s", cidr, "-o", ifName, "-j", "MASQUERADE"},
	}
}

func ipForwardRules(cidr, ifName string) []iptablesRule {
	return []iptablesRule{
		{
			chain: "FORWARD",
			args:  []string{"-s", cidr, "-o", ifName, "-j", "ACCEPT"},
		},
		{
			chain: "FORWARD",
			args: []string{
				"-d", cidr,
				"-i", ifName,
				"-m", "state",
				"--state", "RELATED,ESTABLISHED",
				"-j", "ACCEPT",
			},
		},
	}
}

func tcpMSSClampRule(tcpMSS uint16) iptablesRule {
	args := []string{
		"-p", "tcp",
		"-m", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
	}
	if tcpMSS == 0 {
		args = append(args, "--clamp-mss-to-pmtu")
	} else {
		args = append(args, "--set-mss", fmt.Sprintf("%d", tcpMSS))
	}

	return iptablesRule{
		table: "mangle",
		chain: "FORWARD",
		args:  args,
	}
}
