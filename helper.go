// SPDX-FileCopyrightText: 2024 Dominik Wombacher <dominik@wombacher.cc>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"C"
	"fmt"
	"time"
)

func recordToString(count int, tag *C.char, timestamp time.Time, record map[interface{}]interface{}) string {
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("[%d] %s: [%s, {", count, C.GoString(tag), timestamp.String()))
	for k, v := range parseMap(record) {
		buffer.WriteString(fmt.Sprintf("\"%s\": %v, ", k, v))
	}
	buffer.WriteString("}\n")

	return buffer.String()
}

func printRecord(count int, tag *C.char, timestamp time.Time, record map[interface{}]interface{}) {
	fmt.Printf("[%d] %s: [%s, {", count, C.GoString(tag), timestamp.String())
	for k, v := range parseMap(record) {
		fmt.Printf("\"%s\": %v, ", k, v)
	}
	fmt.Print("}\n")
}