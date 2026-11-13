package forwarder

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/go-upf/pkg/factory"
)

// The gtp5g device is the one that gtpu.ifList[0].ifname names, and "upfgtp" when it names none,
// so that two UPFs in one network namespace (an I-UPF and its anchor) can each have their own.
func TestGtpuInterface(t *testing.T) {
	cases := []struct {
		name   string
		ifList []factory.IfInfo
		addr   string
		mtu    uint32
		link   string
	}{
		{
			name:   "ifname given",
			ifList: []factory.IfInfo{{Addr: "127.0.0.28", Type: "N9", IfName: "upfgtp2", MTU: 1400}},
			addr:   "127.0.0.28:2152",
			mtu:    1400,
			link:   "upfgtp2",
		},
		{
			name:   "no ifname",
			ifList: []factory.IfInfo{{Addr: "127.0.0.8", Type: "N3"}},
			addr:   "127.0.0.8:2152",
			link:   "upfgtp",
		},
		{
			name: "the first interface's ifname",
			ifList: []factory.IfInfo{
				{Addr: "127.0.0.8", Type: "N3", IfName: "gtpif"},
				{Addr: "127.0.0.9", Type: "N9", IfName: "other"},
			},
			addr: "127.0.0.8:2152",
			link: "gtpif",
		},
		{
			name: "no interface",
			link: "upfgtp",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, mtu, link := gtpuInterface(tc.ifList)
			require.Equal(t, tc.addr, addr)
			require.Equal(t, tc.mtu, mtu)
			require.Equal(t, tc.link, link)
		})
	}
}
