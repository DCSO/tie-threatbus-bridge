// tie-threatbus-bridge
// Copyright (c) 2021, DCSO GmbH

package main

func MakeIOC(indicator, datatype string) IOC {
	return IOC{
		Value:    indicator,
		DataType: datatype,
	}
}
