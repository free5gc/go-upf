package forwarder

import (
	"net"
	"os"
	"syscall"

	"github.com/khirono/go-gtp5gnl"
	"github.com/khirono/go-nl"
	"github.com/khirono/go-rtnllink"
	"github.com/khirono/go-rtnlroute"
)

type Gtp5gLink struct {
	mux    *nl.Mux
	rtconn *nl.Conn
	client *nl.Client
	link   *gtp5gnl.Link
	conn   *net.UDPConn
	f      *os.File
}

func OpenGtp5gLink(mux *nl.Mux, addr string) (*Gtp5gLink, error) {
	g := new(Gtp5gLink)

	g.mux = mux

	rtconn, err := nl.Open(syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	g.rtconn = rtconn
	g.client = nl.NewClient(rtconn, mux)

	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		g.Close()
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		g.Close()
		return nil, err
	}
	g.conn = conn

	// TODO: Duplicate fd
	f, err := conn.File()
	if err != nil {
		g.Close()
		return nil, err
	}
	g.f = f

	linkinfo := &nl.Attr{
		Type: syscall.IFLA_LINKINFO,
		Value: nl.AttrList{
			{
				Type:  rtnllink.IFLA_INFO_KIND,
				Value: nl.AttrString("gtp5g"),
			},
			{
				Type: rtnllink.IFLA_INFO_DATA,
				Value: nl.AttrList{
					{
						Type:  gtp5gnl.IFLA_FD1,
						Value: nl.AttrU32(f.Fd()),
					},
					{
						Type:  gtp5gnl.IFLA_HASHSIZE,
						Value: nl.AttrU32(131072),
					},
				},
			},
		},
	}
	err = rtnllink.Create(g.client, "upfgtp", linkinfo)
	if err != nil {
		g.Close()
		return nil, err
	}
	err = rtnllink.Up(g.client, "upfgtp")
	if err != nil {
		g.Close()
		return nil, err
	}
	link, err := gtp5gnl.GetLink("upfgtp")
	if err != nil {
		g.Close()
		return nil, err
	}
	g.link = link
	return g, nil
}

func (g *Gtp5gLink) Close() {
	if g.f != nil {
		g.f.Close()
	}
	if g.conn != nil {
		g.conn.Close()
	}
	if g.link != nil {
		rtnllink.Remove(g.client, "upfgtp")
	}
	if g.rtconn != nil {
		g.rtconn.Close()
	}
}

func (g *Gtp5gLink) RouteAdd(dst *net.IPNet) error {
	r := &rtnlroute.Request{
		Header: rtnlroute.Header{
			Table:    syscall.RT_TABLE_MAIN,
			Scope:    syscall.RT_SCOPE_UNIVERSE,
			Protocol: syscall.RTPROT_STATIC,
			Type:     syscall.RTN_UNICAST,
		},
	}
	err := r.AddDst(dst)
	if err != nil {
		return err
	}
	err = r.AddIfName(g.link.Name)
	if err != nil {
		return err
	}
	return rtnlroute.Create(g.client, r)
}

func (g *Gtp5gLink) WriteTo(b []byte, addr net.Addr) (int, error) {
	return g.conn.WriteTo(b, addr)
}
