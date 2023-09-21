// tie-threatbus-bridge
// Copyright (c) 2020, 2023, DCSO GmbH

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	link "github.com/tent/http-link-go"
)

type TIECollectorConfig struct {
	URL           string        `yaml:"baseurl"`
	Enable        bool          `yaml:"enable"`
	APIVersion    int           `yaml:"api-version"`
	Token         string        `yaml:"token"`
	Categories    []string      `yaml:"categories"`
	DataTypes     []string      `yaml:"data-types"`
	Since         time.Duration `yaml:"since"`
	TimeQueryName string        `yaml:"time-query-name"`
	ChunkSize     int           `yaml:"chunk-size"`
	Severity      struct {
		From int `yaml:"from"`
		To   int `yaml:"to"`
	} `yaml:"severity"`
	Limit struct {
		Total uint64 `yaml:"total"`
	} `yaml:"limit"`
}

type TIECollector struct {
}

// IOC defines the basic data structure of IOCs in TIE
type IOC struct {
	ID                    string   `json:"id"`
	Value                 string   `json:"value"`
	DataType              string   `json:"data_type"`
	EntityIDs             []string `json:"entity_ids"`
	EventIDs              []string `json:"event_ids"`
	EventAttributes       []string `json:"event_attributes"`
	Categories            []string `json:"categories"`
	SourcePseudonyms      []string `json:"source_pseudonyms"`
	SourceNames           []string `json:"source_names"`
	NOccurrences          int      `json:"n_occurrences"`
	MinSeverity           int      `json:"min_severity"`
	MaxSeverity           int      `json:"max_severity"`
	MinConfidence         int      `json:"min_confidence"`
	MaxConfidence         int      `json:"max_confidence"`
	Enrich                bool     `json:"enrich"`
	ObservationAttributes []string `json:"observation_attributes"`
}

// IOCParams contains all necessary query parameters
type IOCParams struct {
	NoDefaults       bool     `json:"no_defaults"`
	Direction        string   `json:"direction"`
	OrderBy          string   `json:"order_by"`
	Severity         string   `json:"severity"`
	Confidence       string   `json:"confidence"`
	Ivalue           string   `json:"ivalue"`
	GroupBy          []string `json:"group_by"`
	Limit            int      `json:"limit"`
	Offset           int      `json:"offset"`
	WithCompositions bool     `json:"with_compositions"`
	DateField        string   `json:"date_field"`
	Enriched         bool     `json:"enriched"`
	DateFormat       string   `json:"date_format"`
}

// IOCQueryStruct defines the returned data of a TIE API IOC query
type IOCQueryStruct struct {
	HasMore bool      `json:"has_more"`
	Iocs    []IOC     `json:"iocs"`
	Params  IOCParams `json:"params"`
}

type queryFunc func(u *url.URL) url.Values

func queryAllTIE(u *url.URL) url.Values {
	q := u.Query()
	if len(Config.Collectors.TIE.Categories) > 0 {
		q.Add("category", strings.Join(Config.Collectors.TIE.Categories, ","))
	}
	if len(Config.Collectors.TIE.DataTypes) > 0 {
		q.Add("data_type", strings.Join(Config.Collectors.TIE.DataTypes, ","))
	}
	q.Add(Config.Collectors.TIE.TimeQueryName, time.Now().Add(-Config.Collectors.TIE.Since).Format("2006-01-02T15:04:05.000000Z"))
	q.Add("severity", fmt.Sprintf("%d-%d", Config.Collectors.TIE.Severity.From,
		Config.Collectors.TIE.Severity.To))
	log.Debug(q)
	return q
}

func (m *TIECollector) getIOCForQuery(query queryFunc, outChan chan IOC) (uint64, uint64, error) {
	offset := 0
	limit := Config.Collectors.TIE.ChunkSize
	retryCount := 0
	url := Config.Collectors.TIE.URL
	iocCount := uint64(0)

	filterOutCategories := map[string]bool{
		"sinkhole":                 true,
		"parking":                  true,
		"potential-false-positive": true,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return iocCount, 0, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", Config.Collectors.TIE.Token))
	q := query(req.URL)
	q.Add("offset", fmt.Sprintf("%d", offset))
	q.Add("limit", fmt.Sprintf("%d", limit))
	q.Add("order_by", "seq")
	req.URL.RawQuery = q.Encode()

	buf := make(map[string][]IOC)
	for {
		log.Debugf("TIE: requesting %v", req.URL)
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return iocCount, 0, err
		}
		defer resp.Body.Close()
		var qryRes IOCQueryStruct

		log.Debug("response status:", resp.Status)

		if resp.StatusCode == http.StatusOK {
			retryCount = 0
			err = json.NewDecoder(resp.Body).Decode(&qryRes)
			if err != nil {
				log.Errorf("error decoding JSON: %s", err.Error())
			}
			for _, val := range qryRes.Iocs {
				keep := true
				for _, c := range val.Categories {
					if _, ok := filterOutCategories[c]; ok {
						keep = false
						break
					}
				}
				if keep {
					if _, ok := buf[val.DataType]; !ok {
						buf[val.DataType] = make([]IOC, 0)
					}
					iocCount++
					buf[val.DataType] = append(buf[val.DataType], val)
				}
			}
			if !qryRes.HasMore {
				log.Debug("no more data")
				break
			} else {
				log.Debug("more data available")
				if fetchLink := resp.Header.Get("link"); fetchLink != "" {
					links, err := link.Parse(fetchLink)
					if err != nil {
						log.Errorf("parse link: %v", err)
						break
					}
					for _, l := range links {
						if l.Rel == "next" {
							req, err = http.NewRequest("GET", l.URI, nil)
							if err != nil {
								log.Error(err)
							}
							req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", Config.Collectors.TIE.Token))
							break
						}
					}
				}
			}
		} else {
			retryCount++
			log.Warnf("%d-%d: received status %v, retrying (try %d)", offset, offset+limit-1, resp.Status, retryCount)
			if retryCount == 3 {
				log.Errorf("skipping TIE queries after 3 unsuccessful retries")
				break
			}
		}
	}

	var i uint64
	// process types defined in configuration first, in given order
	for _, t := range Config.Collectors.TIE.DataTypes {
		if vals, ok := buf[t]; ok {
			for _, val := range vals {
				if Config.Collectors.TIE.Limit.Total == 0 || i < Config.Collectors.TIE.Limit.Total {
					outChan <- val
					i++
				} else {
					break
				}
			}
		}
	}
	// process all others
	for k, v := range buf {
		alreadyHandled := false
		for _, t := range Config.Collectors.TIE.DataTypes {
			if t == k {
				alreadyHandled = true
				break
			}
		}
		if !alreadyHandled {
			for _, val := range v {
				if Config.Collectors.TIE.Limit.Total == 0 || i < Config.Collectors.TIE.Limit.Total {
					outChan <- val
					i++
				} else {
					break
				}
			}
		}
	}
	return iocCount, i, nil
}

func (m *TIECollector) Name() string {
	return "TIE"
}

func (m *TIECollector) Configure() error {
	return nil
}

func (m *TIECollector) Fetch(out chan IOC) (uint64, uint64, error) {
	log.Debug(Config)
	cnt, sent, err := m.getIOCForQuery(queryAllTIE, out)
	return cnt, sent, err
}
