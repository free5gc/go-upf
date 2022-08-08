package report

type ReportType int

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
	MeasureRpt  MeasureReport
	QueryUrrRef uint32
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

func (r USAReport) Type() ReportType {
	return USAR
}

type MeasureReport interface {
	Type() MeasurementType
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

type DurationMeasure struct {
	DurationValue uint64
}

func (m DurationMeasure) Type() MeasurementType {
	return MEASURE_DURAT
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
