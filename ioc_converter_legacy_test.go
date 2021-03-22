// tie-threatbus-bridge
// Copyright (c) 2021, DCSO GmbH

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIOCConverterLegacyDomain(t *testing.T) {
	// {"ts":"2021-03-18T19:29:31.555292569+01:00","id":"intel_c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2","data":{"indicator":["foobar"],"intel_type":11},"operation":"ADD"}
	c := MakeIOCConverterLegacy()
	ioc := MakeIOC("foobar", "DomainName")
	v, err := c.FromIOC(&ioc)
	if err != nil {
		t.Fatalf("error creating json: %s", err.Error())
	}
	var i interface{}
	err = json.Unmarshal(v, &i)
	if err != nil {
		t.Fatalf("error parsing json: %s", err.Error())
	}
	if !strings.Contains(string(v), `"data":{"indicator":["foobar"],"intel_type":11},"operation":"ADD"`) {
		t.Fatalf("invalid result: %s", string(v))
	}
}

func TestIOCConverterLegacyURL(t *testing.T) {
	// {"ts":"2021-03-18T19:31:59.751183469+01:00","id":"intel_c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2","data":{"indicator":["foobar"],"intel_type":13},"operation":"ADD"}
	c := MakeIOCConverterLegacy()
	ioc := MakeIOC("foobar", "URLVerbatim")
	v, err := c.FromIOC(&ioc)
	if err != nil {
		t.Fatalf("error creating json: %s", err.Error())
	}
	var i interface{}
	err = json.Unmarshal(v, &i)
	if err != nil {
		t.Fatalf("error parsing json: %s", err.Error())
	}
	if !strings.Contains(string(v), `"data":{"indicator":["foobar"],"intel_type":13},"operation":"ADD"`) {
		t.Fatalf("invalid result: %s", string(v))
	}
}
