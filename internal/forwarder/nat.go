package forwarder

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
)

type NatRule struct {
	CIDR   string
	IfName string
}

type commandRunner func(name string, args ...string) error

type NatManager struct {
	run        commandRunner
	ownedRules []NatRule
	mu         sync.Mutex
}

func NewNatManager() *NatManager {
	return newNatManager(runCommand)
}

func newNatManager(run commandRunner) *NatManager {
	return &NatManager{
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

func (m *NatManager) AddMasquerade(cidr, ifName string) error {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("invalid NAT CIDR %q: %w", cidr, err)
	}
	if _, err := net.InterfaceByName(ifName); err != nil {
		return fmt.Errorf(
			"natifname %q not found in current network namespace; "+
				"use an interface visible to the UPF process, or leave natifname empty and route %s externally: %w",
			ifName, cidr, err)
	}

	rule := NatRule{CIDR: cidr, IfName: ifName}
	checkArgs := masqueradeArgs("-C", rule)
	if err := m.run("iptables", checkArgs...); err == nil {
		return nil
	}

	appendArgs := masqueradeArgs("-A", rule)
	if err := m.run("iptables", appendArgs...); err != nil {
		return fmt.Errorf("install NAT MASQUERADE rule for %s via %s: %w", cidr, ifName, err)
	}

	m.mu.Lock()
	m.ownedRules = append(m.ownedRules, rule)
	m.mu.Unlock()
	return nil
}

func (m *NatManager) Cleanup() []error {
	m.mu.Lock()
	rules := append([]NatRule(nil), m.ownedRules...)
	m.ownedRules = nil
	m.mu.Unlock()

	var errs []error
	for i := len(rules) - 1; i >= 0; i-- {
		rule := rules[i]
		if err := m.run("iptables", masqueradeArgs("-D", rule)...); err != nil {
			errs = append(errs, fmt.Errorf("delete NAT MASQUERADE rule for %s via %s: %w", rule.CIDR, rule.IfName, err))
		}
	}
	return errs
}

func masqueradeArgs(op string, rule NatRule) []string {
	return []string{
		"-t", "nat",
		op, "POSTROUTING",
		"-s", rule.CIDR,
		"-o", rule.IfName,
		"-j", "MASQUERADE",
	}
}
