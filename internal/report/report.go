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
	}
	if r.USARTrigger.START == 0 && r.USARTrigger.STOPT == 0 && r.USARTrigger.MACAR == 0 {
		// These IEs shall be present, except if the Usage Report
		// Trigger indicates 'Start of Traffic', 'Stop of Traffic' or 'MAC
		// Addresses Reporting'.
		ies = append(ies, ie.NewStartTime(r.StartTime), ie.NewEndTime(r.EndTime))
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
	}
	if r.USARTrigger.START == 0 && r.USARTrigger.STOPT == 0 && r.USARTrigger.MACAR == 0 {
		// These IEs shall be present, except if the Usage Report
		// Trigger indicates 'Start of Traffic', 'Stop of Traffic' or 'MAC
		// Addresses Reporting'.
		ies = append(ies, ie.NewStartTime(r.StartTime), ie.NewEndTime(r.EndTime))
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
	}
	if r.USARTrigger.START == 0 && r.USARTrigger.STOPT == 0 && r.USARTrigger.MACAR == 0 {
		// These IEs shall be present, except if the Usage Report
		// Trigger indicates 'Start of Traffic', 'Stop of Traffic' or 'MAC
		// Addresses Reporting'.
		ies = append(ies, ie.NewStartTime(r.StartTime), ie.NewEndTime(r.EndTime))
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

func (t *UsageReportTrigger) ToOctects() []uint8 {
	return []uint8{
		t.PERIO | t.VOLTH<<1 | t.TIMTH<<2 | t.QUHTI<<3 | t.START<<4 | t.STOPT<<5 | t.DROTH<<6 | t.IMMER<<7,
		t.VOLQU | t.TIMQU<<1 | t.LIUSA<<2 | t.TERMR<<3 | t.MONIT<<4 | t.ENVCL<<5 | t.MACAR<<6 | t.EVETH<<7,
		t.EVEQU | t.TEBUR<<1 | t.IPMJL<<2 | t.QUVTI<<3 | t.EMRRE<<4,
	}
}

func (t *UsageReportTrigger) Unmarshal(v uint32) {
	t.EVEQU = uint8(v & 1)
	t.TEBUR = uint8((v >> 1) & 1)
	t.IPMJL = uint8((v >> 2) & 1)
	t.QUVTI = uint8((v >> 3) & 1)
	t.EMRRE = uint8((v >> 4) & 1)

	t.VOLQU = uint8((v >> 8) & 1)
	t.TIMQU = uint8((v >> 9) & 1)
	t.LIUSA = uint8((v >> 10) & 1)
	t.TERMR = uint8((v >> 11) & 1)
	t.MONIT = uint8((v >> 12) & 1)
	t.ENVCL = uint8((v >> 13) & 1)
	t.MACAR = uint8((v >> 14) & 1)
	t.EVETH = uint8((v >> 15) & 1)

	t.PERIO = uint8((v >> 16) & 1)
	t.VOLTH = uint8((v >> 17) & 1)
	t.TIMTH = uint8((v >> 18) & 1)
	t.QUHTI = uint8((v >> 19) & 1)
	t.START = uint8((v >> 20) & 1)
	t.STOPT = uint8((v >> 21) & 1)
	t.DROTH = uint8((v >> 22) & 1)
	t.IMMER = uint8((v >> 23) & 1)
}

type MeasureReport interface {
	Type() MeasurementType
	IE() *ie.IE
}

type VolumeMeasure struct {
	Flags          uint8
	TotalVolume    uint64
	UplinkVolume   uint64
	DownlinkVolume uint64
	TotalPktNum    uint64
	UplinkPktNum   uint64
	DownlinkPktNum uint64
}

func (m *VolumeMeasure) Type() MeasurementType {
	return MEASURE_VOLUM
}

func (m *VolumeMeasure) IE() *ie.IE {
	return ie.NewVolumeMeasurement(
		m.Flags,
		m.TotalVolume,
		m.UplinkVolume,
		m.DownlinkVolume,
		m.TotalPktNum,
		m.UplinkPktNum,
		m.DownlinkPktNum,
	)
}

const (
	TOVOL uint8 = 1 << iota
	ULVOL
	DLVOL
	TONOP
	ULNOP
	DLNOP
)

func (m *VolumeMeasure) SetTotalVolume(v uint64) {
	if v > 0 {
		m.Flags |= TOVOL
		m.TotalVolume = v
	}
}

func (m *VolumeMeasure) SetUplinkVolume(v uint64) {
	if v > 0 {
		m.Flags |= ULVOL
		m.UplinkVolume = v
	}
}

func (m *VolumeMeasure) SetDownlinkVolume(v uint64) {
	if v > 0 {
		m.Flags |= DLVOL
		m.DownlinkVolume = v
	}
}

func (m *VolumeMeasure) SetTotalPktNum(n uint64) {
	if n > 0 {
		m.Flags |= TONOP
		m.TotalPktNum = n
	}
}

func (m *VolumeMeasure) SetUplinkPktNum(n uint64) {
	if n > 0 {
		m.Flags |= ULNOP
		m.UplinkPktNum = n
	}
}

func (m *VolumeMeasure) SetDownlinkPktNum(n uint64) {
	if n > 0 {
		m.Flags |= DLNOP
		m.DownlinkPktNum = n
	}
}

type DurationMeasure struct {
	DurationValue uint64
}

func (m *DurationMeasure) Type() MeasurementType {
	return MEASURE_DURAT
}

func (m *DurationMeasure) IE() *ie.IE {
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
