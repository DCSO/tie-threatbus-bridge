// tie-threatbus-bridge
// Copyright (c) 2020, DCSO GmbH

package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
	"time"

	zmq "github.com/pebbe/zmq4"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

var (
	tc       Collector
	updating bool
	socket   *zmq.Socket
)

func update(iocChan chan IOC) {
	defer func() {
		log.Info("Update finished")
		updating = false
	}()
	log.Info("Updating")
	tc.Fetch(iocChan)
}

type IOCJSON struct {
	TS   time.Time `json:"ts"`
	ID   string    `json:"id"`
	Data struct {
		Indicator []string `json:"indicator"`
		IntelType int      `json:"intel_type"`
	} `json:"data"`
	Operation string `json:"operation"`
}

func sendZMQ(ioc *IOC) error {
	tbIOCType := mapTIEtoThreatBus(ioc.DataType)
	if tbIOCType < 0 {
		return fmt.Errorf("invalid data type: %s", ioc.DataType)
	}
	iocJSON := IOCJSON{
		TS: time.Now(),
		ID: fmt.Sprintf("intel_%x", sha256.Sum256([]byte(ioc.Value))),
		Data: struct {
			Indicator []string `json:"indicator"`
			IntelType int      `json:"intel_type"`
		}{
			Indicator: []string{ioc.Value},
			IntelType: tbIOCType,
		},
		Operation: "ADD",
	}
	j, err := json.Marshal(iocJSON)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("threatbus/intel %s", string(j))
	i, err := socket.Send(msg, 0)
	log.Debug("Sending ", msg)
	if err != nil {
		return err
	}
	log.Debug(i, " sent")

	return nil
}

func main() {
	var err error
	var configFilename = flag.String("config", "config.yaml", "configuration file")
	var verbose = flag.Bool("verbose", false, "be verbose")

	flag.Parse()

	iocChan := make(chan IOC, 10000)

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	log.SetFormatter(UTCFormatter{&log.JSONFormatter{}})

	yamlFile, err := ioutil.ReadFile(*configFilename)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(yamlFile, &Config)
	if err != nil {
		log.Fatal(err)
	}

	go func(myIocChan chan IOC) {
		for ioc := range myIocChan {
			err := sendZMQ(&ioc)
			if err != nil {
				log.Error(err)
			}
		}
	}(iocChan)

	context, _ := zmq.NewContext()
	socket, err = context.NewSocket(zmq.PUB)
	if err != nil {
		log.Fatal(err)
	}
	err = socket.Connect(fmt.Sprintf("tcp://%s:%d", Config.ThreatBusConfig.Host, Config.ThreatBusConfig.Port))
	if err != nil {
		log.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)

	tc = &TIECollector{}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGUSR1)
	go func() {
		for sig := range c {
			log.Debug(sig)
			if sig == syscall.SIGTERM || sig == syscall.SIGINT {
				log.Info("Shutting down")
				if socket != nil {
					socket.Close()
				}
				os.Exit(0)
			} else if sig == syscall.SIGUSR1 {
				if !updating {
					updating = true
					go update(iocChan)
				} else {
					log.Info("Update in progress")
				}
			}
		}
	}()

	select {}
}
