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
	Fetch(chan IOC) (uint64, error)
	Configure() error
	Name() string
}

type ThreatBusConfig struct {
	Host string
	Port int
}
