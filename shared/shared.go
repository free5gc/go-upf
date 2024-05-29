package shared

import "time"

type to_fill_the_report struct {
	QFI                      uint8
	QoSMonitoringMeasurement uint32
	EventTimeStamp           time.Time
	StartTime                time.Time
}
