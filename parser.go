// SPDX-FileCopyrightText: 2022 Stefan Majer <stefan.majer@f-i-ts.de>
//
// SPDX-License-Identifier: Apache-2.0

package main

/*
	https://github.com/majst01/fluent-bit-go-redis-output/blob/master/out_redis.go
*/
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
