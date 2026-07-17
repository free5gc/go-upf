package forwarder

import (
	"errors"
	"strings"
	"testing"
)

type commandCall struct {
	name string
	args []string
}

func TestIptablesManagerAddDNNRulesRuleAlreadyExists(t *testing.T) {
	var calls []commandCall
	m := newIptablesManager(func(name string, args ...string) error {
		calls = append(calls, commandCall{name: name, args: append([]string(nil), args...)})
		return nil
	})

	if err := m.AddDNNRules("10.60.0.0/16", "lo", true); err != nil {
		t.Fatalf("AddDNNRules returned error: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("expected three iptables -C calls, got %d calls", len(calls))
	}
	assertCommand(t, calls[0], "iptables", []string{
		"-t", "nat", "-C", "POSTROUTING", "-s", "10.60.0.0/16", "-o", "lo", "-j", "MASQUERADE",
	})
	assertCommand(t, calls[1], "iptables", []string{
		"-C", "FORWARD", "-s", "10.60.0.0/16", "-o", "lo", "-j", "ACCEPT",
	})
	assertCommand(t, calls[2], "iptables", []string{
		"-C", "FORWARD", "-d", "10.60.0.0/16", "-i", "lo", "-m", "state", "--state",
		"RELATED,ESTABLISHED", "-j", "ACCEPT",
	})

	if errs := m.Cleanup(); len(errs) != 0 {
		t.Fatalf("expected no cleanup errors, got %v", errs)
	}
	if len(calls) != 3 {
		t.Fatalf("expected cleanup not to delete pre-existing rules, got %d calls", len(calls))
	}
}

func TestIptablesManagerAddAndCleanupOwnedRules(t *testing.T) {
	var calls []commandCall
	m := newIptablesManager(func(name string, args ...string) error {
		calls = append(calls, commandCall{name: name, args: append([]string(nil), args...)})
		if len(args) >= 2 && args[0] == "-C" || len(args) >= 4 && args[2] == "-C" {
			return errors.New("rule not found")
		}
		return nil
	})

	if err := m.AddDNNRules("10.60.0.0/16", "lo", true); err != nil {
		t.Fatalf("AddDNNRules returned error: %v", err)
	}
	if len(calls) != 6 {
		t.Fatalf("expected check and append calls for three rules, got %d calls", len(calls))
	}
	assertCommand(t, calls[1], "iptables", []string{
		"-t", "nat", "-A", "POSTROUTING", "-s", "10.60.0.0/16", "-o", "lo", "-j", "MASQUERADE",
	})
	assertCommand(t, calls[3], "iptables", []string{
		"-A", "FORWARD", "-s", "10.60.0.0/16", "-o", "lo", "-j", "ACCEPT",
	})
	assertCommand(t, calls[5], "iptables", []string{
		"-A", "FORWARD", "-d", "10.60.0.0/16", "-i", "lo", "-m", "state", "--state",
		"RELATED,ESTABLISHED", "-j", "ACCEPT",
	})

	if errs := m.Cleanup(); len(errs) != 0 {
		t.Fatalf("expected no cleanup errors, got %v", errs)
	}
	if len(calls) != 9 {
		t.Fatalf("expected cleanup delete calls for three rules, got %d calls", len(calls))
	}
	assertCommand(t, calls[6], "iptables", []string{
		"-D", "FORWARD", "-d", "10.60.0.0/16", "-i", "lo", "-m", "state", "--state",
		"RELATED,ESTABLISHED", "-j", "ACCEPT",
	})
	assertCommand(t, calls[7], "iptables", []string{
		"-D", "FORWARD", "-s", "10.60.0.0/16", "-o", "lo", "-j", "ACCEPT",
	})
	assertCommand(t, calls[8], "iptables", []string{
		"-t", "nat", "-D", "POSTROUTING", "-s", "10.60.0.0/16", "-o", "lo", "-j", "MASQUERADE",
	})
}

func TestIptablesManagerSkipsForwardRulesWhenDisabled(t *testing.T) {
	var calls []commandCall
	m := newIptablesManager(func(name string, args ...string) error {
		calls = append(calls, commandCall{name: name, args: append([]string(nil), args...)})
		if len(args) >= 4 && args[2] == "-C" {
			return errors.New("rule not found")
		}
		return nil
	})

	if err := m.AddDNNRules("10.60.0.0/16", "lo", false); err != nil {
		t.Fatalf("AddDNNRules returned error: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected only check and append calls for MASQUERADE, got %d calls", len(calls))
	}
	assertCommand(t, calls[1], "iptables", []string{
		"-t", "nat", "-A", "POSTROUTING", "-s", "10.60.0.0/16", "-o", "lo", "-j", "MASQUERADE",
	})
}

func TestIptablesManagerRejectsMissingInterface(t *testing.T) {
	m := newIptablesManager(func(name string, args ...string) error {
		t.Fatalf("iptables should not be called when interface is missing")
		return nil
	})

	err := m.AddDNNRules("10.60.0.0/16", "definitely-missing-upf-iface", true)
	if err == nil {
		t.Fatal("expected missing interface error")
	}
	if !strings.Contains(err.Error(), "not found in current network namespace") {
		t.Fatalf("expected network namespace guidance, got %v", err)
	}
}

func TestIptablesManagerRejectsInvalidCIDR(t *testing.T) {
	m := newIptablesManager(func(name string, args ...string) error {
		t.Fatalf("iptables should not be called when CIDR is invalid")
		return nil
	})

	if err := m.AddDNNRules("not-a-cidr", "lo", true); err == nil {
		t.Fatal("expected invalid CIDR error")
	}
}

func assertCommand(t *testing.T, got commandCall, wantName string, wantArgs []string) {
	t.Helper()
	if got.name != wantName {
		t.Fatalf("command name = %q, want %q", got.name, wantName)
	}
	if len(got.args) != len(wantArgs) {
		t.Fatalf("command args = %v, want %v", got.args, wantArgs)
	}
	for i := range wantArgs {
		if got.args[i] != wantArgs[i] {
			t.Fatalf("command args = %v, want %v", got.args, wantArgs)
		}
	}
}
