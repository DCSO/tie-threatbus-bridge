// tie-threatbus-bridge
// Copyright (c) 2020, 2023, DCSO GmbH

package main

type GlobalConfig struct {
	Collectors struct {
		TIE TIECollectorConfig `yaml:"tie"`
	} `yaml:"collectors"`
	ThreatBusConfig ThreatBusConfig `yaml:"threatbus"`
	Logfile         string          `yaml:"logfile"`
}

var Config GlobalConfig

type Collector interface {
	Fetch(chan IOC) (uint64, uint64, error)
	Configure() error
	Name() string
}

type ThreatBusConfig struct {
	Host   string
	Port   int
	Format string
}
