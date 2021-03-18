// tie-threatbus-bridge
// Copyright (c) 2021, DCSO GmbH

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIOCConverterSTIX2Domain(t *testing.T) {
	c := MakeIOCConverterSTIX2()
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
	if !strings.Contains(string(v), `[domain-name:value = 'foobar']`) {
		t.Fatalf("invalid result: %s", string(v))
	}
}

func TestIOCConverterSTIX2URL(t *testing.T) {
	c := MakeIOCConverterSTIX2()
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
	if !strings.Contains(string(v), `[url:value = 'foobar']`) {
		t.Fatalf("invalid result: %s", string(v))
	}
}
