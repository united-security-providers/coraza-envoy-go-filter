package main

import (
	"strconv"
)

func BuildLoggerMessage() messageTemplate {
	buff := make([]byte, 0)
	return &defaultMessage{buff: buff}
}

type messageTemplate interface {
	msg(msg string) string
	str(key, val string) messageTemplate
	err(err error) messageTemplate
}

type defaultMessage struct {
	buff []byte
}

func (d *defaultMessage) msg(msg string) string {
	if len(msg) == 0 {
		return string(d.buff)
	}
	d.buff = append(d.buff, ' ')
	d.buff = append(d.buff, "msg="...)
	d.buff = append(d.buff, msg...)
	return string(d.buff)
}

func (d *defaultMessage) str(key, val string) messageTemplate {
	d.buff = append(d.buff, ' ')
	d.buff = append(d.buff, key...)
	d.buff = append(d.buff, '=')
	d.buff = append(d.buff, strconv.Quote(val)...)
	return d
}

func (d *defaultMessage) err(err error) messageTemplate {
	if err == nil {
		return d
	}
	d.buff = append(d.buff, "error=\""...)
	d.buff = append(d.buff, err.Error()...)
	d.buff = append(d.buff, "\""...)
	return d
}
