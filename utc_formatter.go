// tie-threatbus-bridge
// Copyright (c) 2021, DCSO GmbH

package main

import (
	log "github.com/sirupsen/logrus"
)

type UTCFormatter struct {
	log.Formatter
}

func (u UTCFormatter) Format(e *log.Entry) ([]byte, error) {
	e.Time = e.Time.UTC()
	return u.Formatter.Format(e)
}
