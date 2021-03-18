// tie-threatbus-bridge
// Copyright (c) 2021, DCSO GmbH

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIOCConverterLegacyDomain(t *testing.T) {
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
