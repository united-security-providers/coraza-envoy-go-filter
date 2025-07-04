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
func BuildLoggerMessage(logformat string) LogMessageBuilder {
	buff := make([]byte, 0)
	return &BasicLogMessage{
		buff:   buff,
		data:   make(map[string]interface{}),
		format: logformat,
	}
}

type LogMessageBuilder interface {
	msg(msg string) LogMessageBuilder
	str(key, val string) LogMessageBuilder
	err(err error) LogMessageBuilder
	output() string
}

type BasicLogMessage struct {
	buff   []byte                 // buffer for plaintext output
	data   map[string]interface{} // data for json output
	format string                 // store the logformat
}

func (d *BasicLogMessage) msg(msg string) LogMessageBuilder {
	d.buff = append(d.buff, ' ')
	d.buff = append(d.buff, "msg="...)
	d.buff = append(d.buff, msg...)
	d.data["msg"] = msg
	return d
}

func (d *BasicLogMessage) str(key, val string) LogMessageBuilder {
	d.buff = append(d.buff, ' ')
	d.buff = append(d.buff, key...)
	d.buff = append(d.buff, '=')
	d.buff = append(d.buff, strconv.Quote(val)...)
	d.data[key] = val
	return d
}

func (d *BasicLogMessage) err(err error) LogMessageBuilder {
	if err == nil {
		return d
	}
	d.buff = append(d.buff, "error=\""...)
	d.buff = append(d.buff, err.Error()...)
	d.buff = append(d.buff, "\""...)
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
