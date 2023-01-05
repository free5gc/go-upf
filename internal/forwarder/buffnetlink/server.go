package buffnetlink

import (
	"encoding/binary"
	"sync"
	"syscall"

	"github.com/khirono/go-genl"
	"github.com/khirono/go-nl"
	"github.com/pkg/errors"

	"github.com/free5gc/go-gtp5gnl"
	"github.com/free5gc/go-upf/internal/report"
)

type Server struct {
	client  *nl.Client
	mux     *nl.Mux
	conn    *nl.Conn
	handler report.Handler
}

var native binary.ByteOrder = gtp5gnl.NativeEndian()

func OpenServer(wg *sync.WaitGroup, client *nl.Client, mux *nl.Mux) (*Server, error) {
	s := &Server{
		client: client,
		mux:    mux,
	}

	f, err := genl.GetFamily(s.client, "gtp5g")
	if err != nil {
		return nil, errors.Wrap(err, "get family")
	}

	s.conn, err = nl.Open(syscall.NETLINK_GENERIC, int(f.Groups[gtp5gnl.GENL_MCGRP].ID))
	if err != nil {
		return nil, errors.Wrap(err, "open netlink")
	}

	err = s.mux.PushHandler(s.conn, s)
	if err != nil {
		return nil, errors.Wrap(err, "push handler")
	}

	// wg.Add(1)
	return s, nil
}

func (s *Server) Close() {
	s.mux.PopHandler(s.conn)
	s.conn.Close()
}

func (s *Server) Handle(handler report.Handler) {
	s.handler = handler
}

func (s *Server) ServeMsg(msg *nl.Msg) bool {
	b := msg.Body[genl.SizeofHeader:]

	var pkt []byte
	var seid uint64
	var pdrid uint16
	var action uint16

	for len(b) > 0 {
		hdr, n, err := nl.DecodeAttrHdr(b)
		if err != nil {
			return false
		}
		switch hdr.MaskedType() {
		case gtp5gnl.BUFFER_ID:
			pdrid = native.Uint16(b[n:])
		case gtp5gnl.BUFFER_ACTION:
			action = native.Uint16(b[n:])
		case gtp5gnl.BUFFER_SEID:
			seid = native.Uint64(b[n:])
		case gtp5gnl.BUFFER_PACKET:
			pkt = b[n:int(hdr.Len)]
		}
		b = b[hdr.Len.Align():]
	}

	if s.handler != nil && pkt != nil {
		dldr := report.DLDReport{
			PDRID:  pdrid,
			Action: action,
			BufPkt: pkt,
		}
		s.handler.NotifySessReport(
			report.SessReport{
				SEID:    seid,
				Reports: []report.Report{dldr},
			},
		)
	}

	return true
}

func (s *Server) Pop(seid uint64, pdrid uint16) ([]byte, bool) {
	return s.handler.PopBufPkt(seid, pdrid)
}
