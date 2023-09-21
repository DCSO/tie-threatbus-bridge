// tie-threatbus-bridge
// Copyright (c) 2023, DCSO GmbH

package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"testing"

	"github.com/jarcoal/httpmock"
)

func TestTIECollector_getIOCForQuery(t *testing.T) {
	type args struct {
		query   queryFunc
		outChan chan IOC
	}
	tests := []struct {
		name    string
		m       *TIECollector
		args    args
		want    uint64
		want1   uint64
		wantErr bool
	}{
		{
			name: "test",
			m:    &TIECollector{},
			args: struct {
				query   queryFunc
				outChan chan IOC
			}{
				query:   queryAllTIE,
				outChan: make(chan IOC),
			},
			want:  1000,
			want1: 900,
		},
	}

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	var domainCount, urlCount uint64
	httpmock.RegisterResponder("GET", "http://testtie",
		func(req *http.Request) (*http.Response, error) {
			iocs := make([]IOC, 1000)
			for i := 0; i < 1000; i++ {
				if rand.Intn(100)%2 == 0 {
					iocs[i] = IOC{
						DataType: "URLVerbatim",
						Value:    fmt.Sprintf("http://url%d.com", i),
					}
					urlCount++
				} else {
					iocs[i] = IOC{
						DataType: "DomainName",
						Value:    fmt.Sprintf("domain%d.net", i),
					}
					domainCount++
				}
			}
			t.Logf("domains %v urls %v", domainCount, urlCount)
			res := IOCQueryStruct{
				HasMore: false,
				Iocs:    iocs,
			}
			resp, err := httpmock.NewJsonResponse(200, res)
			if err != nil {
				return httpmock.NewStringResponse(500, ""), nil
			}
			return resp, nil
		})

	Config = GlobalConfig{
		Collectors: struct {
			TIE TIECollectorConfig `yaml:"tie"`
		}{
			TIE: TIECollectorConfig{
				URL:    "http://testtie",
				Enable: true,
				DataTypes: []string{
					"DomainName",
					"URLVerbatim",
				},
				Limit: struct {
					Total uint64 "yaml:\"total\""
				}{
					Total: 900,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &TIECollector{}

			var wg sync.WaitGroup
			ctx, cancel := context.WithCancel(context.TODO())
			coll := make([]IOC, 0)
			go func(ctx context.Context, ch chan IOC, wg *sync.WaitGroup) {
				for {
					select {
					case <-ctx.Done():
						return
					case v := <-ch:
						coll = append(coll, v)
						wg.Done()
					}
				}
			}(ctx, tt.args.outChan, &wg)

			wg.Add(int(tt.want1))
			got, got1, err := m.getIOCForQuery(tt.args.query, tt.args.outChan)
			wg.Wait()
			cancel()

			if (err != nil) != tt.wantErr {
				t.Errorf("TIECollector.getIOCForQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("TIECollector.getIOCForQuery() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("TIECollector.getIOCForQuery() got1 = %v, want %v", got1, tt.want1)
			}
			var gotDomainCount, gotUrlCount uint64
			for _, v := range coll {
				switch v.DataType {
				case "DomainName":
					gotDomainCount++
				case "URLVerbatim":
					gotUrlCount++
				}
			}
			if gotDomainCount != domainCount {
				t.Errorf("TIECollector.getIOCForQuery() gotDomainCount = %v, domainCount %v", gotDomainCount, domainCount)
			}
			if gotUrlCount != urlCount-(tt.want-tt.want1) {
				t.Errorf("TIECollector.getIOCForQuery() gotUrlCount = %v, urlCount %v", gotUrlCount, urlCount)
			}
		})
	}
}
