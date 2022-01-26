package report

type Handler interface {
	ServeReport(Report)
}

type HandlerFunc func(Report)

func (f HandlerFunc) ServeReport(r Report) {
	f(r)
}
