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

func TestNatManagerAddMasqueradeRuleAlreadyExists(t *testing.T) {
	var calls []commandCall
	m := newNatManager(func(name string, args ...string) error {
		calls = append(calls, commandCall{name: name, args: append([]string(nil), args...)})
		return nil
	})

	if err := m.AddMasquerade("10.60.0.0/16", "lo"); err != nil {
		t.Fatalf("AddMasquerade returned error: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected only iptables -C call, got %d calls", len(calls))
	}
	assertCommand(t, calls[0], "iptables", []string{"-t", "nat", "-C", "POSTROUTING", "-s", "10.60.0.0/16", "-o", "lo", "-j", "MASQUERADE"})

	if errs := m.Cleanup(); len(errs) != 0 {
		t.Fatalf("expected no cleanup errors, got %v", errs)
	}
	if len(calls) != 1 {
		t.Fatalf("expected cleanup not to delete pre-existing rule, got %d calls", len(calls))
	}
}

func TestNatManagerAddAndCleanupOwnedRule(t *testing.T) {
	var calls []commandCall
	m := newNatManager(func(name string, args ...string) error {
		calls = append(calls, commandCall{name: name, args: append([]string(nil), args...)})
		if len(args) >= 4 && args[2] == "-C" {
			return errors.New("rule not found")
		}
		return nil
	})

	if err := m.AddMasquerade("10.60.0.0/16", "lo"); err != nil {
		t.Fatalf("AddMasquerade returned error: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected check and append calls, got %d calls", len(calls))
	}
	assertCommand(t, calls[1], "iptables", []string{"-t", "nat", "-A", "POSTROUTING", "-s", "10.60.0.0/16", "-o", "lo", "-j", "MASQUERADE"})

	if errs := m.Cleanup(); len(errs) != 0 {
		t.Fatalf("expected no cleanup errors, got %v", errs)
	}
	if len(calls) != 3 {
		t.Fatalf("expected cleanup delete call, got %d calls", len(calls))
	}
	assertCommand(t, calls[2], "iptables", []string{"-t", "nat", "-D", "POSTROUTING", "-s", "10.60.0.0/16", "-o", "lo", "-j", "MASQUERADE"})
}

func TestNatManagerRejectsMissingInterface(t *testing.T) {
	m := newNatManager(func(name string, args ...string) error {
		t.Fatalf("iptables should not be called when interface is missing")
		return nil
	})

	err := m.AddMasquerade("10.60.0.0/16", "definitely-missing-upf-iface")
	if err == nil {
		t.Fatal("expected missing interface error")
	}
	if !strings.Contains(err.Error(), "not found in current network namespace") {
		t.Fatalf("expected network namespace guidance, got %v", err)
	}
}

func TestNatManagerRejectsInvalidCIDR(t *testing.T) {
	m := newNatManager(func(name string, args ...string) error {
		t.Fatalf("iptables should not be called when CIDR is invalid")
		return nil
	})

	if err := m.AddMasquerade("not-a-cidr", "lo"); err == nil {
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
