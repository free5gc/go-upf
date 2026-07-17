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

func (m *IptablesManager) AddDNNRules(cidr, ifName string, ipForwardEnable bool) error {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("invalid NAT CIDR %q: %w", cidr, err)
	}
	if _, err := net.InterfaceByName(ifName); err != nil {
		return fmt.Errorf(
			"natifname %q not found in current network namespace; "+
				"use an interface visible to the UPF process, or leave natifname empty and route %s externally: %w",
			ifName, cidr, err)
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
	return nil
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
