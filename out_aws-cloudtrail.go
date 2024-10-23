// SPDX-FileCopyrightText: 2024 Dominik Wombacher <dominik@wombacher.cc>
// SPDX-FileCopyrightText: 2020 Jonas-Taha El Sesiy <github@elsesiy.com>
// SPDX-FileCopyrightText: 2017 Leah Petersen <leahnpetersen@gmail.com>
// SPDX-FileCopyrightText: 2016 Eduardo Silva <eduardo@treasure-data.com>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"C"
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"os"
	"time"
	"unsafe"

	"github.com/fluent/fluent-bit-go/output"
	"github.com/gofrs/uuid/v5"
	"github.com/sirupsen/logrus"
)

const (
	Version     = "v0.0.1"
	eventSource = "fluent-bit-output-plugin-aws-cloudtrail"
	eventName   = "Fluent Bit: Output Plugin for AWS CloudTrail"
)

// Global vars, only set in 'FLBPluginInit', then expected to be read-only
var params = &Params{}

//export FLBPluginRegister
func FLBPluginRegister(def unsafe.Pointer) int {
	// Gets called only once when the plugin.so is loaded
	return output.FLBPluginRegister(def, "aws-cloudtrail", "Fluent Bit output plugin to ingest events into AWS CloudTrail Lake")
}

//export FLBPluginInit
func FLBPluginInit(plugin unsafe.Pointer) int {
	// Gets called only once for each instance you have configured.

	SetupLogger()

	// CloudTrail Lake Channel Arn mandatory for 'PutAuditEvents'
	channelArnParam := output.FLBPluginConfigKey(plugin, "ChannelArn")
	channelArnEnvVar := os.Getenv("AWS_CLOUDTRAIL_DATA_CHANNELARN")
	if channelArnParam != "" {
		params.ChannelArn = channelArnParam
	} else if channelArnEnvVar != "" {
		params.ChannelArn = channelArnEnvVar
	} else {
		logrus.Error("Environment Variable 'AWS_CLOUDTRAIL_DATA_CHANNELARN' or Fluent Bit plugin parameter 'ChannelArn' required.")
		return output.FLB_ERROR
	}
	logrus.Debugf("ChannelArn: %s", params.ChannelArn)

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

	// Load AWS Config from default chain
	sdkCtx := context.Background()
	sdkConfig, err := config.LoadDefaultConfig(sdkCtx)
	if err != nil {
		logrus.Errorf("Couldn't load AWS default configuration. Error: %v", err)
		return output.FLB_ERROR
	}

	// Create STS Client and retrieve CallerIdentity
	client := sts.NewFromConfig(sdkConfig)
	input := &sts.GetCallerIdentityInput{}
	req, err := client.GetCallerIdentity(sdkCtx, input)
	if err != nil {
		logrus.Errorf("AWS GetCallerIdentity failed. Error: %v", err)
		return output.FLB_ERROR
	}

	logrus.Debugf("AWS Account: %s, AWS UserId: %s, AWS Region: %s", *req.Account, *req.UserId, sdkConfig.Region)

	/*
		Hardcoded to 'User' for now, unclear how it's used and what other values make sense
		CloudTrail Lake Schema defines it as 'string' with a max length of 128 chars.
	*/
	userIdentityType := "User"

	// Values come from AWS STS GetCallerIdentity
	userIdentityPrincipalId := *req.UserId
	recipientAccountId := *req.Account

	// One AuditEvent appended per Fluent Bit record in loop
	putAuditEvents := &PutAuditEvents{
		AuditEvents: []AuditEvent{},
	}

	// Iterate Records
	count = 0
	for {
		// Extract Record
		ret, ts, record = output.GetRecord(dec)
		if ret != 0 {
			break
		}

		// Convert provided time or use Now for timestamp
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

		logrus.Debug(recordToString(count, tag, timestamp, record))

		// 'eventTime' in CloudTrail event schema requires format 'yyyy-MM-DDTHH:mm:ssZ'
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

	// ToDo: Add logic for cloudtrail-data put-audit-events

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
