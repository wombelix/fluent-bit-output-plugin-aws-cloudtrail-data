// SPDX-FileCopyrightText: 2024 Dominik Wombacher <dominik@wombacher.cc>
// SPDX-FileCopyrightText: 2020 Jonas-Taha El Sesiy <github@elsesiy.com>
// SPDX-FileCopyrightText: 2017 Leah Petersen <leahnpetersen@gmail.com>
// SPDX-FileCopyrightText: 2016 Eduardo Silva <eduardo@treasure-data.com>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"C"
	"encoding/json"
	"fmt"
	"time"
	"unsafe"

	"github.com/fluent/fluent-bit-go/output"
)

//export FLBPluginRegister
func FLBPluginRegister(def unsafe.Pointer) int {
	// Gets called only once when the plugin.so is loaded
	return output.FLBPluginRegister(def, "aws-cloudtrail", "Fluent Bit output plugin to ingest events into AWS CloudTrail Lake")
}

//export FLBPluginInit
func FLBPluginInit(plugin unsafe.Pointer) int {
	// Gets called only once for each instance you have configured.
	return output.FLB_OK
}

//export FLBPluginFlushCtx
func FLBPluginFlushCtx(ctx, data unsafe.Pointer, length C.int, tag *C.char) int {
	var count int
	var ret int
	var ts interface{}
	var record map[interface{}]interface{}

	// Create Fluent Bit decoder
	dec := output.NewDecoder(data, int(length))

	// Iterate Records
	count = 0
	for {
		// Extract Record
		ret, ts, record = output.GetRecord(dec)
		if ret != 0 {
			break
		}

		var timestamp time.Time
		switch t := ts.(type) {
		case output.FLBTime:
			timestamp = ts.(output.FLBTime).Time
		case uint64:
			timestamp = time.Unix(int64(t), 0)
		default:
			fmt.Println("time provided invalid, defaulting to now.")
			timestamp = time.Now()
		}

		js, err := createJSON(record)
		if err != nil {
			// Report and skip faulty record
			fmt.Printf("%v\n", err)
			continue
		}

		fmt.Printf("[%d] %s: [%s, {", count, C.GoString(tag), timestamp.String())
		fmt.Printf("%s", js)
		fmt.Printf("}\n")

		count++
	}

	// Return options:
	//
	// output.FLB_OK    = data have been processed.
	// output.FLB_ERROR = unrecoverable error, do not try this again.
	// output.FLB_RETRY = retry to flush later.
	return output.FLB_OK
}

//export FLBPluginExit
func FLBPluginExit() int {
	return output.FLB_OK
}

func main() {
}

// SPDX-FileCopyrightText: 2022 Stefan Majer <stefan.majer@f-i-ts.de>
//
// SPDX-License-Identifier: Apache-2.0
func parseMap(mapInterface map[interface{}]interface{}) map[string]interface{} {
	m := make(map[string]interface{})
	for k, v := range mapInterface {
		switch t := v.(type) {
		case []byte:
			// prevent encoding to base64
			m[k.(string)] = string(t)
		case map[interface{}]interface{}:
			m[k.(string)] = parseMap(t)
		default:
			m[k.(string)] = v
		}
	}
	return m
}

// SPDX-FileCopyrightText: 2022 Stefan Majer <stefan.majer@f-i-ts.de>
//
// SPDX-License-Identifier: Apache-2.0
func createJSON(record map[interface{}]interface{}) ([]byte, error) {
	m := parseMap(record)

	js, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("error creating message: %w", err)
	}
	return js, nil
}

// ToDo:
//
//	id has to be unique and generated for each auditEvents put
type AuditEvent struct {
	EventData EventData `json:"eventData"`
	Id        string    `json:"id"`
}

// ToDo:
//
//	Version should match the plugin release version
//	UserIdentity has to be filled with data from current aws session / identity
//	EventTime has to be the current time in form of '2024-10-10T11:16:08Z'
//	UID has to be unique and generated for each auditEvents put
//	AwsRegion region where the events get pushed to
//	RecipientAccountId account where the events get pushed to
//	AdditionalEventData contains the payload, received from NeuVector as json in the syslog message
type EventData struct {
	Version             string       `json:"page"`
	UserIdentity        UserIdentity `json:"userIdentity"`
	EventSource         string       `json:"eventSource"`
	EventName           string       `json:"eventName"`
	EventTime           string       `json:"eventTime"`
	UID                 string
	AwsRegion           string   `json:"awsRegion"`
	RecipientAccountId  string   `json:"recipientAccountId"`
	AdditionalEventData []string `json:"additionalEventData"`
}

type UserIdentity struct {
	Type        string `json:"type"`
	PrincipalId string `json:"principalId"`
}
