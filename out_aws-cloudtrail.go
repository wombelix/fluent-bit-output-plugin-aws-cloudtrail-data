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
	"log"
	"time"
	"unsafe"

	"github.com/fluent/fluent-bit-go/output"
	"github.com/gofrs/uuid/v5"
)

var Version = "v0.0.1"

//export FLBPluginRegister
func FLBPluginRegister(def unsafe.Pointer) int {
	// Gets called only once when the plugin.so is loaded
	return output.FLBPluginRegister(def, "aws-cloudtrail", "Fluent Bit output plugin to ingest events into AWS CloudTrail Lake")
}

//export FLBPluginInit
func FLBPluginInit(plugin unsafe.Pointer) int {
	// Gets called only once for each instance you have configured.

	param := output.FLBPluginConfigKey(plugin, "param")
	fmt.Printf("[flb-go] plugin parameter = '%s'\n", param)

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

	// Define vars needed as part of the 'PutAuditEvents' call
	putAuditEvents := &PutAuditEvents{
		AuditEvents: []AuditEvent{},
	}
	userIdentityType := "User"
	userIdentityPrincipalId := "AROA123456789EXAMPLE:ExampleRole"
	recipientAccountId := "111122223333"

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

		// Needs logic to output only in debug mode, to noise for info
		fmt.Printf("[%d] %s: [%s, {", count, C.GoString(tag),
			timestamp.String())
		for k, v := range parseMap(record) {
			fmt.Printf("\"%s\": %v, ", k, v)
		}
		fmt.Printf("}\n")

		// Define vars needed as part of the 'PutAuditEvents' call
		timestampRFC3339 := timestamp.Format(time.RFC3339)
		uuidAuditEvent := generateUUID()
		uuidEventData := generateUUID()

		eventData := &EventData{
			Version: Version,
			UserIdentity: UserIdentity{
				Type:        userIdentityType,
				PrincipalId: userIdentityPrincipalId,
			},
			EventSource:         "fluent-bit-output-plugin-aws-cloudtrail",
			EventName:           "Fluent Bit: Output Plugin for AWS CloudTrail",
			EventTime:           timestampRFC3339,
			UID:                 uuidEventData,
			RecipientAccountId:  recipientAccountId,
			AdditionalEventData: parseMap(record),
		}

		eventDataJson, err := json.Marshal(eventData)
		if err != nil {
			log.Printf("error creating message: %s", err)
		}

		auditEvent := &AuditEvent{
			EventData: string(eventDataJson),
			Id:        uuidAuditEvent,
		}

		putAuditEvents.AuditEvents = append(
			putAuditEvents.AuditEvents, *auditEvent)

		count++
	}

	// Needs logging logic to provide JSON output if fluentbit runs with debug flag
	//js, err := json.MarshalIndent(putAuditEvents, "", "  ")
	//js, err := json.Marshal(putAuditEvents)
	//if err != nil {
	//	log.Fatalf("error creating message: %w", err)
	//}
	//fmt.Printf("%s", js)

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

func generateUUID() string {
	// Create a Version 4 UUID.
	uuidV4, err := uuid.NewV4()
	if err != nil {
		log.Printf("failed to generate UUID: %s", err) // ToDo: Error loggig but not failing at this point, FLBPluginFlushCtx has to return output.FLB_ERROR
	}

	return uuidV4.String()
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

type PutAuditEvents struct {
	AuditEvents []AuditEvent `json:"auditEvents"`
}

type AuditEvent struct {
	EventData string `json:"eventData"`
	Id        string `json:"id"`
}

// ToDo:
//
//	UserIdentity has to be filled with data from current aws session / identity
//	RecipientAccountId account where the events get pushed to
type EventData struct {
	Version             string       `json:"version"`
	UserIdentity        UserIdentity `json:"userIdentity"`
	EventSource         string       `json:"eventSource"`
	EventName           string       `json:"eventName"`
	EventTime           string       `json:"eventTime"`
	UID                 string
	RecipientAccountId  string                 `json:"recipientAccountId"`
	AdditionalEventData map[string]interface{} `json:"additionalEventData"`
}

type UserIdentity struct {
	Type        string `json:"type"`
	PrincipalId string `json:"principalId"`
}
