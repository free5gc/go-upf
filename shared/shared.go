package shared

import "time"

// this struct will be filled and sent to the report code inside pfcp to fill the report!
type ToBeReported struct {
	QFI                      uint8
	QoSMonitoringMeasurement uint32
	EventTimeStamp           time.Time //change to uint32
	StartTime                time.Time //change to uint32
}

type Mointor interface {
	GetValuesChan() <-chan ToBeReported
}
