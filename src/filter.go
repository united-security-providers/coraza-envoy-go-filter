//  Copyright © 2023 Axkea, spacewander
//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

const HOSTPOSTSEPARATOR string = ":"

type filter struct {
	callbacks                   api.FilterCallbackHandler
	conf                        configuration
	wafMaps                     wafMaps
	tx                          types.Transaction
	httpProtocol                string
	isInterruption              bool
	processRequestBody          bool
	processResponseBody         bool
	withNoResponseBodyProcessed bool
}

func (f *filter) DecodeHeaders(headerMap api.RequestHeaderMap, endStream bool) api.StatusType {
	var host string
	host = headerMap.Host()
	if len(host) == 0 {
		return api.Continue
	}
	waf := f.conf.wafMaps[f.conf.defaultDirective]
	ruleName, ok := f.conf.hostDirectiveMap[host]
	if ok {
		waf = f.conf.wafMaps[ruleName]
	}

	xReqId, exist := headerMap.Get("x-request-id")
	if !exist {
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.msg("Error getting x-request-id header")
		f.callbacks.Log(api.Info, logger.output())
		xReqId = ""
	}

	// the ID of the transaction is set to the ID of the request
	// see errorCallback() in parse.go for more details
	f.tx = waf.NewTransactionWithID(xReqId)
	f.tx.AddRequestHeader("Host", host)
	var server = host
	var err error
	if strings.Contains(host, HOSTPOSTSEPARATOR) {
		server, _, err = net.SplitHostPort(host)
		if err != nil {
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.str("Host", host)
			logger.err(err)
			logger.msg("Failed to parse server name from Host")
			f.callbacks.Log(api.Info, logger.output())
			f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
	}
	f.tx.SetServerName(server)
	tx := f.tx
	//X-Coraza-Rule-Engine: Off  This can be set through the request header
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	srcIP, srcPortString, _ := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamRemoteAddress())
	srcPort, err := strconv.Atoi(srcPortString)
	if err != nil {
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.err(err)
		logger.msg("RemotePort formatting error")
		f.callbacks.Log(api.Info, logger.output())
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	destIP, destPortString, _ := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamLocalAddress())
	destPort, err := strconv.Atoi(destPortString)
	if err != nil {
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.err(err)
		logger.msg("LocalPort formatting error")
		f.callbacks.Log(api.Info, logger.output())
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	tx.ProcessConnection(srcIP, srcPort, destIP, destPort)
	path := headerMap.Path()
	method := headerMap.Method()
	protocol, ok := f.callbacks.StreamInfo().Protocol()
	if !ok {
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.msg("Protocol not set")
		f.callbacks.Log(api.Warn, logger.output())
		protocol = "HTTP/2.0"
	}
	f.httpProtocol = protocol
	tx.ProcessURI(path, method, protocol)
	headerMap.Range(func(key, value string) bool {
		tx.AddRequestHeader(key, value)
		return true
	})
	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		f.isInterruption = true
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.msg("ProcessRequestHeaders failed")
		f.callbacks.Log(api.Info, logger.output())
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	return api.Continue
}

func (f *filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.isInterruption {
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "interruption-already-handled")
		return api.LocalReply
	}
	if f.processRequestBody {
		return api.Continue
	}
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !tx.IsRequestBodyAccessible() {
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.msg("Skipping request body inspection, SecRequestBodyAccess is off")
		f.callbacks.Log(api.Debug, logger.output())
		f.processRequestBody = true
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.err(err)
			logger.msg("Failed to process request body")
			f.callbacks.Log(api.Info, logger.output())
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.msg("ProcessRequestBody forbidden")
			f.callbacks.Log(api.Info, logger.output())
			f.callbacks.DecoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
		return api.Continue
	}
	bodySize := buffer.Len()
	logger := BuildLoggerMessage(f.conf.logFormat)
	logger.str("size", strconv.Itoa(bodySize))
	logger.msg("Processing incoming request data")
	f.callbacks.Log(api.Trace, logger.output())
	if bodySize > 0 {
		bytes := buffer.Bytes()
		interruption, buffered, err := tx.WriteRequestBody(bytes)
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.str("size", strconv.Itoa(buffered))
		logger.msg("Buffered request data")
		f.callbacks.Log(api.Trace, logger.output())
		if err != nil {
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.err(err)
			logger.msg("Failed to write request body")
			f.callbacks.Log(api.Info, logger.output())
			return api.Continue
		}

		/* WriteRequestBody triggers ProcessRequestBody if the bodylimit (SecRequestBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by request body processing.
		 */
		if interruption != nil {
			f.isInterruption = true
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.msg("WriteRequestBody interrupted")
			f.callbacks.Log(api.Info, logger.output())
			f.callbacks.DecoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
	}
	if endStream {
		f.processRequestBody = true
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.err(err)
			logger.msg("Failed to process request body")
			f.callbacks.Log(api.Info, logger.output())
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.msg("ProcessRequestBody failed")
			f.callbacks.Log(api.Info, logger.output())
			f.callbacks.DecoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
		return api.Continue
	}
	return api.StopAndBuffer
}

func (f *filter) DecodeTrailers(trailerMap api.RequestTrailerMap) api.StatusType {
	return api.Continue
}

func (f filter) EncodeHeaders(headerMap api.ResponseHeaderMap, endStream bool) api.StatusType {
	if f.isInterruption {
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.msg("Interruption already handled, sending downstream the local response")
		f.callbacks.Log(api.Debug, logger.output())
		return api.Continue
	}
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !f.processRequestBody {
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.msg("ProcessRequestBody in phase3")
		f.callbacks.Log(api.Debug, logger.output())
		f.processRequestBody = true
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.err(err)
			logger.msg("Failed to process request body")
			f.callbacks.Log(api.Info, logger.output())
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.msg("ProcessRequestBody failed")
			f.callbacks.Log(api.Info, logger.output())
			f.callbacks.EncoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
	}
	code, b := f.callbacks.StreamInfo().ResponseCode()
	if !b {
		code = 0
	}
	headerMap.Range(func(key, value string) bool {
		tx.AddResponseHeader(key, value)
		return true
	})
	interruption := tx.ProcessResponseHeaders(int(code), f.httpProtocol)
	if interruption != nil {
		f.isInterruption = true
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.msg("ProcessResponseHeader failed")
		f.callbacks.Log(api.Info, logger.output())
		f.callbacks.EncoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}

	/* if this is not the end of the stream (i.e there is a body) and response
	 * body processing is enabled, we need to buffer the headers to avoid envoy
	 * already sending them downstream to the client before the body processing
	 * eventually changes the status code
	 */
	if !endStream && tx.IsResponseBodyAccessible() {
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.msg("Buffering response headers")
		f.callbacks.Log(api.Debug, logger.output())
		return api.StopAndBuffer
	}

	return api.Continue
}

func (f *filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.isInterruption {
		f.callbacks.EncoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	if f.withNoResponseBodyProcessed {
		return api.Continue
	}
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	bodySize := buffer.Len()
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	logger := BuildLoggerMessage(f.conf.logFormat)
	logger.str("size", strconv.Itoa(bodySize))
	logger.msg("Processing incoming response data")
	f.callbacks.Log(api.Trace, logger.output())
	if !tx.IsResponseBodyAccessible() {
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.msg("Skipping response body inspection, SecResponseBodyAccess is off")
		f.callbacks.Log(api.Debug, logger.output())
		if !f.withNoResponseBodyProcessed {
			// According to documentation, it is recommended to call this method even if it has no body.
			// It permits to execute rules belonging to request body phase, but not necesarily processing the response body.
			interruption, err := tx.ProcessResponseBody()
			f.withNoResponseBodyProcessed = true
			f.processResponseBody = true
			if err != nil {
				logger := BuildLoggerMessage(f.conf.logFormat)
				logger.err(err)
				logger.msg("ProcessResponseBody error")
				f.callbacks.Log(api.Info, logger.output())
				return api.Continue
			}
			if interruption != nil {
				f.isInterruption = true
				logger := BuildLoggerMessage(f.conf.logFormat)
				logger.msg("ProcessResponseBody forbidden")
				f.callbacks.Log(api.Info, logger.output())
				f.callbacks.EncoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
				return api.LocalReply
			}
		}
		return api.Continue
	}
	if bodySize > 0 {
		ResponseBodyBuffer := buffer.Bytes()
		interruption, buffered, err := tx.WriteResponseBody(ResponseBodyBuffer)
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.str("size", strconv.Itoa(buffered))
		logger.msg("Buffered response data")
		f.callbacks.Log(api.Trace, logger.output())
		if err != nil {
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.err(err)
			logger.msg("Failed to write response body")
			f.callbacks.Log(api.Info, logger.output())
			return api.Continue
		}
		/* WriteResponseBody triggers ProcessResponseBody if the bodylimit (SecResponseBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by response body processing.
		 */
		if interruption != nil {
			f.isInterruption = true
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.msg("WriteResponseBody interrupted")
			f.callbacks.Log(api.Info, logger.output())
			f.callbacks.EncoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
	}
	if endStream {
		f.processResponseBody = true
		interruption, err := tx.ProcessResponseBody()
		if err != nil {
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.err(err)
			logger.msg("ProcessResponseBody error")
			f.callbacks.Log(api.Info, logger.output())
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.processResponseBody = true
			buffer.Set(bytes.Repeat([]byte("\x00"), bodySize))
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.err(err)
			logger.msg("ProcessResponseBody failed")
			f.callbacks.Log(api.Info, logger.output())
			f.callbacks.EncoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
		return api.Continue
	}
	return api.StopAndBuffer
}

func (f *filter) EncodeTrailers(trailerMap api.ResponseTrailerMap) api.StatusType {
	return api.Continue
}

func (f *filter) OnLog(api.RequestHeaderMap, api.RequestTrailerMap, api.ResponseHeaderMap, api.ResponseTrailerMap) {
}
func (f *filter) OnLogDownstreamPeriodic(api.RequestHeaderMap, api.RequestTrailerMap, api.ResponseHeaderMap, api.ResponseTrailerMap) {
}
func (f *filter) OnLogDownstreamStart(api.RequestHeaderMap) {}
func (f *filter) OnStreamComplete()                         {}

func (f *filter) OnDestroy(reason api.DestroyReason) {
	tx := f.tx
	if tx != nil {
		if !f.processResponseBody {
			logger := BuildLoggerMessage(f.conf.logFormat)
			logger.msg("Running ProcessResponseBody in OnHttpStreamDone, triggered actions will not be enforced. Further logs are for detection only purposes")
			f.callbacks.Log(api.Debug, logger.output())
			f.processResponseBody = true
			_, err := tx.ProcessResponseBody()
			if err != nil {
				logger := BuildLoggerMessage(f.conf.logFormat)
				logger.err(err)
				logger.msg("Process response body onDestroy error")
				f.callbacks.Log(api.Info, logger.output())
			}
		}
		f.tx.ProcessLogging()
		_ = f.tx.Close()
		logger := BuildLoggerMessage(f.conf.logFormat)
		logger.msg("Finished")
		f.callbacks.Log(api.Info, logger.output())
	}
}

func main() {
}
