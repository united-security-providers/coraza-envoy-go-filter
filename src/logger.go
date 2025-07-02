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
func BuildLoggerMessage(logformat string) messageTemplate {
	buff := make([]byte, 0)
	return &defaultMessage{
		buff:   buff,
		data:   make(map[string]interface{}),
		format: logformat,
	}
}

type messageTemplate interface {
	msg(msg string) messageTemplate
	str(key, val string) messageTemplate
	err(err error) messageTemplate
	output() string
}

type defaultMessage struct {
	buff   []byte                 // buffer for plaintext output
	data   map[string]interface{} // data for json output
	format string                 // store the logformat
}

func (d *defaultMessage) msg(msg string) messageTemplate {
	d.buff = append(d.buff, ' ')
	d.buff = append(d.buff, "msg="...)
	d.buff = append(d.buff, msg...)
	d.data["msg"] = msg
	return d
}

func (d *defaultMessage) str(key, val string) messageTemplate {
	d.buff = append(d.buff, ' ')
	d.buff = append(d.buff, key...)
	d.buff = append(d.buff, '=')
	d.buff = append(d.buff, strconv.Quote(val)...)
	d.data[key] = val
	return d
}

func (d *defaultMessage) err(err error) messageTemplate {
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
func (d *defaultMessage) output() string {
	if d.format == "json" {
		jsonData, err := json.Marshal(d.data)
		if err != nil {
			return "error marshaling to JSON"
		}
		return string(jsonData)
	}
	return string(d.buff)
}
