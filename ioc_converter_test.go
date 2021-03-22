// tie-threatbus-bridge
// Copyright (c) 2021, DCSO GmbH

package main

import "testing"

func TestIOCConverterFactory(t *testing.T) {
	c, err := MakeIOCConverter("legacy")
	if err != nil {
		t.Fatalf("error creating converter for legacy: %s", err.Error())
	}
	if c.Topic() != "threatbus/intel" {
		t.Fatalf("wrong topic: %s", c.Topic())
	}

	c, err = MakeIOCConverter("stix2")
	if err != nil {
		t.Fatalf("error creating converter for stix2: %s", err.Error())
	}
	if c.Topic() != "stix2/indicator" {
		t.Fatalf("wrong topic: %s", c.Topic())
	}
}

func TestIOCConverterFactoryFail(t *testing.T) {
	_, err := MakeIOCConverter("foo")
	if err == nil {
		t.Fatal("no error creating converter for foo")
	}
}
