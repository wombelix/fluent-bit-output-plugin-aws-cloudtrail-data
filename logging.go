// SPDX-FileCopyrightText: 2024 Dominik Wombacher <dominik@wombacher.cc>
// SPDX-FileCopyrightText: 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	fluentBitLogLevelEnvVar = "FLB_LOG_LEVEL"
)

/*
	SetupLogger sets up Logrus with the log level determined by the Fluent Bit Env Var
	https://github.com/aws/amazon-kinesis-firehose-for-fluent-bit/blob/mainline/plugins/plugins.go
*/
func SetupLogger() {
	logrus.SetOutput(os.Stdout)

	switch strings.ToUpper(os.Getenv(fluentBitLogLevelEnvVar)) {
	default:
		logrus.SetLevel(logrus.InfoLevel)
	case "DEBUG":
		logrus.SetLevel(logrus.DebugLevel)
		logrus.SetReportCaller(true)
		logrus.SetFormatter(&logrus.TextFormatter{
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				return f.Function + "()", fmt.Sprintf("%s:%d", path.Base(f.File), f.Line)
			},
		})
	case "INFO":
		logrus.SetLevel(logrus.InfoLevel)
	case "ERROR":
		logrus.SetLevel(logrus.ErrorLevel)
	}
}
