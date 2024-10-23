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
	"time"
	"unsafe"

	"github.com/fluent/fluent-bit-go/output"
	"github.com/gofrs/uuid/v5"
	"github.com/sirupsen/logrus"
)

const (
	Version = "v0.0.1"
	eventSource = "fluent-bit-output-plugin-aws-cloudtrail"
	eventName = "Fluent Bit: Output Plugin for AWS CloudTrail"
)

//export FLBPluginRegister
func FLBPluginRegister(def unsafe.Pointer) int {
	// Gets called only once when the plugin.so is loaded
	return output.FLBPluginRegister(def, "aws-cloudtrail", "Fluent Bit output plugin to ingest events into AWS CloudTrail Lake")
}

//export FLBPluginInit
func FLBPluginInit(plugin unsafe.Pointer) int {
	// Gets called only once for each instance you have configured.

	/*
		param := output.FLBPluginConfigKey(plugin, "param")
		fmt.Printf("[flb-go] plugin parameter = '%s'\n", param)
	*/

	SetupLogger()

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
			logrus.Warning("time provided invalid, defaulting to now.")
			timestamp = time.Now()
		}

		if logrus.GetLevel() == logrus.DebugLevel {
			printRecord(count, tag, timestamp, record)
		}

		// Define vars needed as part of the 'PutAuditEvents' call
		timestampRFC3339 := timestamp.Format(time.RFC3339)

		// ToDo: Refactor to reduce code redundancy
		uuidAuditEvent, err := uuid.NewV4()
		if err != nil {
			logrus.Errorf("Failed to generate UUID (uuidAuditEvent), skipping record.\nError: %v\nRecord: %s",
				err, recordToString(count, tag, timestamp, record))
			continue
		}
		uuidEventData, err := uuid.NewV4()
		if err != nil {
			logrus.Errorf("Failed to generate UUID (uuidEventData), skipping record.\nError: %v\nRecord: %s",
				err, recordToString(count, tag, timestamp, record))
			continue
		}

		eventData := &EventData{
			Version: Version,
			UserIdentity: UserIdentity{
				Type:        userIdentityType,
				PrincipalId: userIdentityPrincipalId,
			},
			EventSource:         eventSource,
			EventName:           eventName,
			EventTime:           timestampRFC3339,
			UID:                 uuidEventData.String(),
			RecipientAccountId:  recipientAccountId,
			AdditionalEventData: parseMap(record),
		}

		// ToDo: Refactor to reduce code redundancy
		eventDataJson, err := json.Marshal(eventData)
		if err != nil {
			logrus.Errorf("Error converting 'eventData' to json, skipping record.\nError: %v\nRecord: %s",
				err, recordToString(count, tag, timestamp, record))
			continue
		}

		auditEvent := &AuditEvent{
			EventData: string(eventDataJson),
			Id:        uuidAuditEvent.String(),
		}

		putAuditEvents.AuditEvents = append(
			putAuditEvents.AuditEvents, *auditEvent)

		count++
	}

	// Not sure if I want it like that, worth re-thinking / re-factoring later
	// Loggig to convert to Json and push to CloudTrail is still missing
	// Debug Json output and error in case of conversion issues should be handled then
	if logrus.GetLevel() == logrus.DebugLevel {
		js, err := json.MarshalIndent(putAuditEvents, "", "  ")
		if err != nil {
			logrus.Errorf("Error converting 'putAuditEvents' to JSON.\nError: %v\nData: %s", err, putAuditEvents)
			return output.FLB_ERROR
		}
		logrus.Debugf("'putAuditEvents' after JSON encoding:\n%s", js)
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
