package bench

import "time"

// ctlRecAt builds a ctl record at t; every ctl record carries a 10 s interval.
func ctlRecAt(t time.Time, c Ctl) Record {
	c.IntervalMS = 10000
	return Record{T: t, Kind: KindCtl, Ctl: &c}
}

// agRecAt builds an agent record at t.
func agRecAt(t time.Time, a AgentSample) Record {
	return Record{T: t, Kind: KindAgent, Agent: &a}
}

// ctlRec builds a ctl record sec seconds after the fixture epoch.
func ctlRec(sec int, c Ctl) Record {
	return ctlRecAt(time.Unix(1700000000+int64(sec), 0).UTC(), c)
}

// agRec builds an agent record sec seconds after the fixture epoch.
func agRec(sec int, a AgentSample) Record {
	return agRecAt(time.Unix(1700000000+int64(sec), 0).UTC(), a)
}
