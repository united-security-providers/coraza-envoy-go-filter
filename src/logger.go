//  Copyright © 2023 Axkea, spacewander
//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strconv"
)

// BuildLoggerMessage creates a new logger with the specified configuration
// logformat can be "plain" or "json"
func BuildLoggerMessage(logformat string) *BasicLogMessage {
	buff := make([]byte, 0)
	return &BasicLogMessage{
		buff:   buff,
		data:   make(map[string]interface{}),
		format: logformat,
	}
}

type BasicLogMessage struct {
	buff   []byte                 // buffer for plaintext output
	data   map[string]interface{} // data for json output
	format string                 // store the logformat
}

func (d *BasicLogMessage) msg(msg string) *BasicLogMessage {
	d.buff = append(d.buff, ' ')
	d.buff = append(d.buff, "msg="...)
	d.buff = append(d.buff, strconv.Quote(msg)...)
	d.data["msg"] = msg
	return d
}

func (d *BasicLogMessage) str(key, val string) *BasicLogMessage {
	d.buff = append(d.buff, ' ')
	d.buff = append(d.buff, key...)
	d.buff = append(d.buff, '=')
	d.buff = append(d.buff, strconv.Quote(val)...)
	d.data[key] = val
	return d
}

func (d *BasicLogMessage) err(err error) *BasicLogMessage {
	if err == nil {
		return d
	}
	d.buff = append(d.buff, ' ')
	d.buff = append(d.buff, "error="...)
	d.buff = append(d.buff, strconv.Quote(err.Error())...)
	d.data["error"] = err.Error()
	return d
}

// output returns the log message in the configured format
func (d *BasicLogMessage) output() string {
	if d.format == "json" {
		jsonData, err := json.Marshal(d.data)
		if err != nil {
			return "error marshaling to JSON"
		}
		return string(jsonData)
	}
	return string(d.buff)
}

// Log builds and immediately returns the log string.
// opts are applied left-to-right and may be:
//
//	string  -> treated as msg (only the first one is kept)
//	error   -> added via err()
//	struct{K,V string} -> added via str(K,V)
func (d *BasicLogMessage) Log(opts ...interface{}) string {
	for _, o := range opts {
		switch v := o.(type) {
		case string: // msg
			d.msg(v)
		case error: // err
			d.err(v)
		case struct{ K, V string }: // str
			d.str(v.K, v.V)
		default:
			panic("logger.go: opt must be string, error, or struct{K,V string}")
		}
	}
	return d.output()
}
