// tie-threatbus-bridge
// Copyright (c) 2021, DCSO GmbH

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIOCConverterSTIX2Domain(t *testing.T) {
	// {"type":"indicator","id":"indicator--42992b91-3ca8-40f6-9f0b-a8c644288663","spec_version":"2.1","created":"2021-03-18T18:32:42.275Z","modified":"2021-03-18T18:32:42.275Z","indicator_types":["malicious-activity"],"pattern":"[domain-name:value = 'foobar']","pattern_type":"stix","valid_from":"2021-03-18T18:32:42.275Z"}
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
	// {"type":"indicator","id":"indicator--b152903a-35e7-412e-8a2e-47fb78d773ba","spec_version":"2.1","created":"2021-03-18T18:32:42.275Z","modified":"2021-03-18T18:32:42.275Z","indicator_types":["malicious-activity"],"pattern":"[url:value = 'foobar']","pattern_type":"stix","valid_from":"2021-03-18T18:32:42.275Z"}
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
