// tie-threatbus-bridge
// Copyright (c) 2021, DCSO GmbH

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// taken from ThreatBus code, starts with 1
const (
	_ = iota
	IPSRC
	IPDST
	IPSRC_PORT
	IPDST_PORT
	EMAILSRC
	EMAILDST
	TARGETEMAIL
	EMAILATTACHMENT
	FILENAME
	HOSTNAME
	DOMAIN
	DOMAIN_IP
	URL
	URI
	USERAGENT
	MD5
	MALWARESAMPLE
	FILENAME_MD5
	SHA1
	FILENAME_SHA1
	SHA256
	FILENAME_SHA256
	X509FINGERPRINTSHA1
	PDB
	AUTHENTIHASH
	SSDEEP
	IMPHASH
	PEHASH
	IMPFUZZY
	SHA224
	SHA384
	SHA512
	SHA512_224
	SHA512_256
	TLSH
	CDHASH
	FILENAME_AUTHENTIHASH
	FILENAME_SSDEEP
	FILENAME_IMPHASH
	FILENAME_PEHASH
	FILENAME_IMPFUZZY
	FILENAME_SHA224
	FILENAME_SHA384
	FILENAME_SHA512
	FILENAME_SHA512_224
	FILENAME_SHA512_256
	FILENAME_TLSH
)

func mapTIEtoThreatBus(iocType string) int {
	switch iocType {
	case "DomainName":
		return DOMAIN
	case "URLVerbatim":
		return URL
	case "PEHash":
		return PEHASH
	case "SSDEEP":
		return SSDEEP
	case "IMPHash":
		return IMPHASH
	case "IPv4":
		return IPSRC // TODO what to do with this? IPDST?
	case "IPv6":
		return IPSRC // TODO what to do with this? IPDST?
	case "FileName":
		return FILENAME
	case "EMail":
		return EMAILSRC // TODO what to do with this? EMAILDST?
	default:
		return -1
	}
}

type IOCConverterLegacy struct{}

func MakeIOCConverterLegacy() *IOCConverterLegacy {
	return &IOCConverterLegacy{}
}

func (c *IOCConverterLegacy) Topic() string {
	return "threatbus/intel"
}

func (c *IOCConverterLegacy) FromIOC(ioc *IOC) ([]byte, error) {
	tbIOCType := mapTIEtoThreatBus(ioc.DataType)
	if tbIOCType < 0 {
		return nil, fmt.Errorf("unsupported data type: %s", ioc.DataType)
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
	data, err := json.Marshal(iocJSON)
	if err != nil {
		return nil, err
	}
	return data, nil
}
