package report

import (
	"time"

	"github.com/wmnsk/go-pfcp/ie"
)

type ReportType int

// 29244-ga0 8.2.21 Report Type
const (
	DLDR ReportType = iota + 1
	USAR
	ERIR
	UPIR
	TMIR
	SESR
	UISR
)

func (t ReportType) String() string {
	str := []string{"", "DLDR", "USAR", "ERIR", "UPIR", "TMIR", "SESR", "UISR"}
	return str[t]
}

type MeasurementType int

// 29244-ga0 8.2.40 Measurement Method
const (
	MEASURE_DURAT MeasurementType = iota + 1
	MEASURE_VOLUM
	MEASURE_EVENT
)

func (t MeasurementType) String() string {
	str := []string{"", "DURATION", "VOLUME", "EVENT"}
	return str[t]
}

type Report interface {
	Type() ReportType
}

type DLDReport struct {
	PDRID  uint16
	Action uint16
	BufPkt []byte
}

func (r DLDReport) Type() ReportType {
	return DLDR
}

type USAReport struct {
	URRID       uint32
	URSEQN      uint32
	USARTrigger UsageReportTrigger
	VolMeasure  VolumeMeasure
	MeasureRpt  MeasureReport
	QueryUrrRef uint32
	StartTime   time.Time
	EndTime     time.Time
}

func (r USAReport) Type() ReportType {
	return USAR
}

func (r USAReport) IEsWithinSessReportReq() []*ie.IE {
	ies := []*ie.IE{
		ie.NewURRID(r.URRID),
		ie.NewURSEQN(r.URSEQN),
		ie.NewUsageReportTrigger(r.USARTrigger.ToOctects()...),
		r.VolMeasure.IE(),
		ie.NewStartTime(r.StartTime),
		ie.NewEndTime(r.EndTime),
	}
	if r.MeasureRpt != nil {
		ies = append(ies, r.MeasureRpt.IE())
	}
	return ies
}

func (r USAReport) IEsWithinSessModRsp() []*ie.IE {
	ies := []*ie.IE{
		ie.NewURRID(r.URRID),
		ie.NewURSEQN(r.URSEQN),
		ie.NewUsageReportTrigger(r.USARTrigger.ToOctects()...),
		r.VolMeasure.IE(),
		ie.NewStartTime(r.StartTime),
		ie.NewEndTime(r.EndTime),
	}
	if r.MeasureRpt != nil {
		ies = append(ies, r.MeasureRpt.IE())
	}
	return ies
}

func (r USAReport) IEsWithinSessDelRsp() []*ie.IE {
	ies := []*ie.IE{
		ie.NewURRID(r.URRID),
		ie.NewURSEQN(r.URSEQN),
		ie.NewUsageReportTrigger(r.USARTrigger.ToOctects()...),
		r.VolMeasure.IE(),
		ie.NewStartTime(r.StartTime),
		ie.NewEndTime(r.EndTime),
	}
	if r.MeasureRpt != nil {
		ies = append(ies, r.MeasureRpt.IE())
	}
	return ies
}

type UsageReportTrigger struct {
	PERIO uint8
	VOLTH uint8
	TIMTH uint8
	QUHTI uint8
	START uint8
	STOPT uint8
	DROTH uint8
	IMMER uint8
	VOLQU uint8
	TIMQU uint8
	LIUSA uint8
	TERMR uint8
	MONIT uint8
	ENVCL uint8
	MACAR uint8
	EVETH uint8
	EVEQU uint8
	TEBUR uint8
	IPMJL uint8
	QUVTI uint8
	EMRRE uint8
}

func (t UsageReportTrigger) ToOctects() []uint8 {
	return []uint8{
		t.PERIO | t.VOLTH<<1 | t.TIMTH<<2 | t.QUHTI<<3 | t.START<<4 | t.STOPT<<5 | t.DROTH<<6 | t.IMMER<<7,
		t.VOLQU | t.TIMQU<<1 | t.LIUSA<<2 | t.TERMR<<3 | t.MONIT<<4 | t.ENVCL<<5 | t.MACAR<<6 | t.EVETH<<7,
		t.EVEQU | t.TEBUR<<1 | t.IPMJL<<2 | t.QUVTI<<3 | t.EMRRE<<4,
	}
}

type MeasureReport interface {
	Type() MeasurementType
	IE() *ie.IE
}

type VolumeMeasure struct {
	TOVOL          uint8
	ULVOL          uint8
	DLVOL          uint8
	TONOP          uint8
	ULNOP          uint8
	DLNOP          uint8
	TotalVolume    uint64
	UplinkVolume   uint64
	DownlinkVolume uint64
	TotalPktNum    uint64
	UplinkPktNum   uint64
	DownlinkPktNum uint64
}

func (m VolumeMeasure) Type() MeasurementType {
	return MEASURE_VOLUM
}

func (m VolumeMeasure) IE() *ie.IE {
	var flags uint8 = (m.DLNOP<<5 |
		m.ULNOP<<4 |
		m.TONOP<<3 |
		m.DLVOL<<2 |
		m.ULVOL<<1 |
		m.TOVOL)
	return ie.NewVolumeMeasurement(
		flags,
		m.TotalVolume,
		m.UplinkVolume,
		m.DownlinkVolume,
		m.TotalPktNum,
		m.UplinkPktNum,
		m.DownlinkPktNum,
	)
}

type DurationMeasure struct {
	DurationValue uint64
}

func (m DurationMeasure) Type() MeasurementType {
	return MEASURE_DURAT
}

func (m DurationMeasure) IE() *ie.IE {
	return ie.NewDurationMeasurement(time.Duration(m.DurationValue))
}

const (
	DROP = 1 << 0
	FORW = 1 << 1
	BUFF = 1 << 2
	NOCP = 1 << 3
)

type SessReport struct {
	SEID    uint64
	Reports []Report
}

type BufInfo struct {
	SEID  uint64
	PDRID uint16
}
