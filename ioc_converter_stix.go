// tie-threatbus-bridge
// Copyright (c) 2021, DCSO GmbH

package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/TcM1911/stix2"
)

func mapTIEtoSTIX2(iocType string) string {
	switch iocType {
	case "DomainName":
		return "[domain-name:value = '%s']"
	case "URLVerbatim":
		return "[url:value = '%s']"
	case "IPv4":
		return "[ipv4-addr:value = '%s']"
	case "IPv6":
		return "[ipv6-addr:value = '%s']"
	case "FileName":
		return "[file:name = '%s']"
	case "EMail":
		return "[email-addr:value = '%s']"
	default:
		return ""
	}
}

type IOCConverterSTIX2 struct{}

func MakeIOCConverterSTIX2() *IOCConverterSTIX2 {
	return &IOCConverterSTIX2{}
}

func (c *IOCConverterSTIX2) Topic() string {
	return "stix2/indicator"
}

func (c *IOCConverterSTIX2) FromIOC(ioc *IOC) ([]byte, error) {
	t := mapTIEtoSTIX2(ioc.DataType)
	if t == "" {
		return nil, fmt.Errorf("unsupported data type: %s", ioc.DataType)
	}
	tsNow := &stix2.Timestamp{
		Time: time.Now().UTC(),
	}
	i, err := stix2.NewIndicator(fmt.Sprintf(t, ioc.Value), "stix", tsNow,
		stix2.OptionCreated(tsNow), stix2.OptionModified(tsNow))
	if err != nil {
		return nil, err
	}
	i.Types = append(i.Types, stix2.IndicatorTypeMaliciousActivity)
	data, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}
	return data, nil
}
