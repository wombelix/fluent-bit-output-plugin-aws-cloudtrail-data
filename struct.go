// SPDX-FileCopyrightText: 2024 Dominik Wombacher <dominik@wombacher.cc>
//
// SPDX-License-Identifier: Apache-2.0

package main

type Params struct {
	ChannelArn string
}

type PutAuditEvents struct {
	AuditEvents []AuditEvent `json:"auditEvents"`
}

type AuditEvent struct {
	EventData string `json:"eventData"`
	Id        string `json:"id"`
}

type UserIdentity struct {
	Type        string `json:"type"`
	PrincipalId string `json:"principalId"`
}

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
