package perio

import (
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
)

const (
	EVENT_CHANNEL_LEN = 512
)

type EventType uint8

const (
	TYPE_PERIO_ADD EventType = iota + 1
	TYPE_PERIO_DEL
	TYPE_PERIO_TIMEOUT
	TYPE_EXPIRY_ADD
	TYPE_EXPIRY_DEL
	TYPE_EXPIRY_TIMEOUT
	TYPE_SERVER_CLOSE
)

func (t EventType) String() string {
	s := []string{
		"", "TYPE_PERIO_ADD", "TYPE_PERIO_DEL", "TYPE_PERIO_TIMEOUT",
		"TYPE_EXPIRY_ADD", "TYPE_EXPIRY_DEL", "TYPE_EXPIRY_TIMEOUT",
		"TYPE_SERVER_CLOSE",
	}
	return s[t]
}

type Event struct {
	eType  EventType
	lSeid  uint64
	urrid  uint32
	period time.Duration
	expiry time.Duration
}

type PERIOGroup struct {
	urrids map[uint64]map[uint32]struct{}
	period time.Duration
	ticker *time.Ticker
	stopCh chan struct{}
}

type Expiry struct {
	lSeid  uint64
	urrid  uint32
	expiry time.Duration
	timer  *time.Timer
}

func (ex *Expiry) newTimer(wg *sync.WaitGroup, evtCh chan Event) error {
	if ex.timer != nil {
		return errors.Errorf("timer not nil")
	}

	ex.timer = time.NewTimer(ex.expiry)
	logger.PerioLog.Warnf("expiry[%v]", ex.expiry)

	wg.Add(1)
	go func(timer *time.Timer, expiry time.Duration, urrid uint32, lSeid uint64, evtCh chan Event) {
		defer func() {
			timer.Stop()
			wg.Done()
		}()

		for {
			select {
			case <-timer.C:
				logger.PerioLog.Debugf("timer[%v] timeout", expiry)
				evtCh <- Event{
					eType:  TYPE_EXPIRY_TIMEOUT,
					expiry: expiry,
					urrid:  urrid,
					lSeid:  lSeid,
				}
				timer.Stop()
			}
		}
	}(ex.timer, ex.expiry, ex.urrid, ex.lSeid, evtCh)

	return nil
}

func (pg *PERIOGroup) newTicker(wg *sync.WaitGroup, evtCh chan Event) error {
	if pg.ticker != nil {
		return errors.Errorf("ticker not nil")
	}

	pg.ticker = time.NewTicker(pg.period)
	pg.stopCh = make(chan struct{})

	wg.Add(1)
	go func(ticker *time.Ticker, period time.Duration, evtCh chan Event) {
		defer func() {
			ticker.Stop()
			wg.Done()
		}()

		for {
			select {
			case <-ticker.C:
				logger.PerioLog.Debugf("ticker[%v] timeout", period)
				evtCh <- Event{
					eType:  TYPE_PERIO_TIMEOUT,
					period: period,
				}
			case <-pg.stopCh:
				logger.PerioLog.Infof("ticker[%v] Stopped", period)
				return
			}
		}
	}(pg.ticker, pg.period, evtCh)

	return nil
}

func (pg *PERIOGroup) stopTicker() {
	pg.stopCh <- struct{}{}
	close(pg.stopCh)
}

type Server struct {
	evtCh      chan Event
	perioList  map[time.Duration]*PERIOGroup // key: period
	expiryList map[uint64](map[uint32]*Expiry)
	handler    report.Handler
	queryURR   func([]uint64, []uint32) (map[uint64][]report.USAReport, error)
}

func OpenServer(wg *sync.WaitGroup) (*Server, error) {
	s := &Server{
		evtCh:      make(chan Event, EVENT_CHANNEL_LEN),
		perioList:  make(map[time.Duration]*PERIOGroup),
		expiryList: make(map[uint64]map[uint32]*Expiry),
	}

	wg.Add(1)
	go s.Serve(wg)
	logger.PerioLog.Infof("perio server started")

	return s, nil
}

func (s *Server) Close() {
	s.evtCh <- Event{eType: TYPE_SERVER_CLOSE}
}

func (s *Server) Handle(
	handler report.Handler,
	queryURR func([]uint64, []uint32) (map[uint64][]report.USAReport, error),
) {
	s.handler = handler
	s.queryURR = queryURR
}

func (s *Server) Serve(wg *sync.WaitGroup) {
	defer func() {
		logger.PerioLog.Infof("perio server stopped")
		close(s.evtCh)
		wg.Done()
	}()

	for e := range s.evtCh {
		logger.PerioLog.Infof("recv event[%s][%+v]", e.eType, e)
		switch e.eType {
		case TYPE_EXPIRY_ADD:
			expiry, ok := s.expiryList[e.lSeid][e.urrid]
			if !ok {
				// New Timer if no this period ticker found
				expiry = &Expiry{
					urrid:  e.urrid,
					expiry: e.expiry,
					lSeid:  e.lSeid,
				}
				if s.expiryList[e.lSeid] == nil {
					s.expiryList[e.lSeid] = map[uint32]*Expiry{}
				}

				err := expiry.newTimer(wg, s.evtCh)
				if err != nil {
					logger.PerioLog.Errorln(err)
					continue
				}

				s.expiryList[e.lSeid][e.urrid] = expiry
			} else {
				expiry.timer.Reset(e.expiry)
			}

		case TYPE_PERIO_ADD:
			perioGroup, ok := s.perioList[e.period]
			if !ok {
				// New ticker if no this period ticker found
				perioGroup = &PERIOGroup{
					urrids: make(map[uint64]map[uint32]struct{}),
					period: e.period,
				}
				err := perioGroup.newTicker(wg, s.evtCh)
				if err != nil {
					logger.PerioLog.Errorln(err)
					continue
				}
				s.perioList[e.period] = perioGroup
			}

			urrids := perioGroup.urrids[e.lSeid]
			if urrids == nil {
				perioGroup.urrids[e.lSeid] = make(map[uint32]struct{})
				perioGroup.urrids[e.lSeid][e.urrid] = struct{}{}
			} else {
				_, ok := perioGroup.urrids[e.lSeid][e.urrid]
				if !ok {
					perioGroup.urrids[e.lSeid][e.urrid] = struct{}{}
				}
			}
		case TYPE_PERIO_DEL:
			for period, perioGroup := range s.perioList {
				_, ok := perioGroup.urrids[e.lSeid][e.urrid]
				if ok {
					// Stop ticker if no more PERIO URR
					delete(perioGroup.urrids[e.lSeid], e.urrid)
					if len(perioGroup.urrids[e.lSeid]) == 0 {
						delete(perioGroup.urrids, e.lSeid)
						if len(perioGroup.urrids) == 0 {
							perioGroup.stopTicker()
						}
						delete(s.perioList, period)
					}
					break
				}
			}
		case TYPE_EXPIRY_TIMEOUT:
			expiry, ok := s.expiryList[e.lSeid][e.urrid]
			if !ok {
				logger.PerioLog.Warnf("no expiry found for urr[%v]", e.urrid)
				break
			}

			expiry.timer.Stop()

			var rpts []report.Report
			sessUsars, err := s.queryURR([]uint64{e.lSeid}, []uint32{e.urrid})
			if err != nil {
				logger.PerioLog.Warnf("get USAReport[%#x:%#x] error: %v", e.lSeid, e.urrid, err)
				break
			}

			if len(sessUsars) == 0 {
				logger.PerioLog.Warnf("no expiry USAReport[%#x:%#x]", e.lSeid, e.urrid)
				continue
			}

			for _, usars := range sessUsars {
				for i := range usars {
					usars[i].USARTrigger.Flags |= report.USAR_TRIG_QUVTI
					rpts = append(rpts, usars[i])
				}
			}

			s.handler.NotifySessReport(
				report.SessReport{
					SEID:    e.lSeid,
					Reports: rpts,
				})

		case TYPE_PERIO_TIMEOUT:
			perioGroup, ok := s.perioList[e.period]
			if !ok {
				logger.PerioLog.Warnf("no periodGroup found for period[%v]", e.period)
				break
			}
			var lSeids []uint64
			var urrIds []uint32
			var rpts []report.Report

			for lSeid, urrids := range perioGroup.urrids {
				for id := range urrids {
					lSeids = append(lSeids, lSeid)
					urrIds = append(urrIds, id)
				}
			}
			sessUsars, err := s.queryURR(lSeids, urrIds)
			if err != nil {
				logger.PerioLog.Warnf("get USAReport[%#x:%#x] error: %v", lSeids, urrIds, err)
				break
			}

			if len(sessUsars) == 0 {
				logger.PerioLog.Warnf("no PERIO USAReport[%#x:%#x]", lSeids, urrIds)
				continue
			}

			for seid, usars := range sessUsars {
				for i := range usars {
					usars[i].USARTrigger.Flags |= report.USAR_TRIG_PERIO
					rpts = append(rpts, usars[i])
				}

				s.handler.NotifySessReport(
					report.SessReport{
						SEID:    seid,
						Reports: rpts,
					})
			}

		case TYPE_SERVER_CLOSE:
			for period, perioGroup := range s.perioList {
				perioGroup.stopTicker()
				delete(s.perioList, period)
			}
			return
		}
	}
}

func (s *Server) AddExpiryTimer(lSeid uint64, urrid uint32, expiry time.Duration) {
	s.evtCh <- Event{
		eType:  TYPE_EXPIRY_ADD,
		lSeid:  lSeid,
		urrid:  urrid,
		expiry: expiry,
	}
}

func (s *Server) DelExpiryTimer(lSeid uint64, urrid uint32) {
	s.evtCh <- Event{
		eType: TYPE_EXPIRY_DEL,
		lSeid: lSeid,
		urrid: urrid,
	}
}

func (s *Server) AddPeriodReportTimer(lSeid uint64, urrid uint32, period time.Duration) {
	s.evtCh <- Event{
		eType:  TYPE_PERIO_ADD,
		lSeid:  lSeid,
		urrid:  urrid,
		period: period,
	}
}

func (s *Server) DelPeriodReportTimer(lSeid uint64, urrid uint32) {
	s.evtCh <- Event{
		eType: TYPE_PERIO_DEL,
		lSeid: lSeid,
		urrid: urrid,
	}
}
