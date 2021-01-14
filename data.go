// tie-threatbus-bridge
// Copyright (c) 2020, DCSO GmbH

package main

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
		return EMAILSRC // TODO what to do with this? IPDST?
	default:
		return -1
	}
}
