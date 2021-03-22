// tie-threatbus-bridge
// Copyright (c) 2021, DCSO GmbH

package main

import "fmt"

type IOCConverter interface {
	Topic() string
	FromIOC(*IOC) ([]byte, error)
}

func MakeIOCConverter(format string) (IOCConverter, error) {
	switch format {
	case "legacy":
		return MakeIOCConverterLegacy(), nil
	case "stix2":
		return MakeIOCConverterSTIX2(), nil
	default:
		return nil, fmt.Errorf("unknown format: %s", format)
	}
}
