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

// enum for connection state, used to detect websocket connections
type ConnectionState int

const (
	HTTP ConnectionState = iota
	UpgradeWebsocketRequested
	WebsocketConnection
)

func (connectionState ConnectionState) String() string {
	return connectionStateName[connectionState]
}

var connectionStateName = map[ConnectionState]string{
	HTTP:                      "http",
	UpgradeWebsocketRequested: "websocket upgrade requested",
	WebsocketConnection:       "websocket connection",
}

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
	connection                  ConnectionState
}

func (f *filter) DecodeHeaders(headerMap api.RequestHeaderMap, endStream bool) api.StatusType {
	f.connection = HTTP

	f.callbacks.Log(api.Debug, BuildLoggerMessage().str("f.connection", f.connection.String()).msg("DecodeHeaders enter"))

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
		f.callbacks.Log(api.Info, BuildLoggerMessage().msg("Error getting x-request-id header"))
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
			f.callbacks.Log(api.Info, BuildLoggerMessage().str("Host", host).err(err).msg("Failed to parse server name from Host"))
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
		f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("RemotePort formatting error"))
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	destIP, destPortString, _ := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamLocalAddress())
	destPort, err := strconv.Atoi(destPortString)
	if err != nil {
		f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("LocalPort formatting error"))
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	tx.ProcessConnection(srcIP, srcPort, destIP, destPort)
	path := headerMap.Path()
	method := headerMap.Method()
	protocol, ok := f.callbacks.StreamInfo().Protocol()
	if !ok {
		f.callbacks.Log(api.Warn, BuildLoggerMessage().msg("Protocol not set"))
		protocol = "HTTP/2.0"
	}
	f.httpProtocol = protocol
	tx.ProcessURI(path, method, protocol)

	upgrade_websocket_header := false
	connection_upgrade_header := false
	headerMap.Range(func(key, value string) bool {
		// check for WS upgrade request
		if key == "upgrade" && strings.Contains(strings.ToLower(value), "websocket") {
			upgrade_websocket_header = true
		}
		if key == "connection" && strings.Contains(strings.ToLower(value), "upgrade") {
			connection_upgrade_header = true

		}
		tx.AddRequestHeader(key, value)
		return true
	})
	if upgrade_websocket_header && connection_upgrade_header {
		f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("detected websocket upgrade request"))
		f.connection = UpgradeWebsocketRequested
	}
	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		f.isInterruption = true
		f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessRequestHeaders failed"))
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	return api.Continue
}

func (f *filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	f.callbacks.Log(api.Debug, BuildLoggerMessage().str("f.connection", f.connection.String()).msg("DecodeData enter"))

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
		f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("Skipping request body inspection, SecRequestBodyAccess is off"))
		f.processRequestBody = true
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("Failed to process request body"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessRequestBody forbidden"))
			f.callbacks.DecoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
		return api.Continue
	}
	bodySize := buffer.Len()
	f.callbacks.Log(api.Trace, BuildLoggerMessage().str("size", strconv.Itoa(bodySize)).msg("Processing incoming request data"))
	if bodySize > 0 {
		bytes := buffer.Bytes()
		interruption, buffered, err := tx.WriteRequestBody(bytes)
		f.callbacks.Log(api.Trace, BuildLoggerMessage().str("size", strconv.Itoa(buffered)).msg("Buffered request data"))
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("Failed to write request body"))
			return api.Continue
		}

		/* WriteRequestBody triggers ProcessRequestBody if the bodylimit (SecRequestBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by request body processing.
		 */
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("WriteRequestBody interrupted"))
			f.callbacks.DecoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
	}
	if endStream {
		f.processRequestBody = true
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("Failed to process request body"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessRequestBody failed"))
			f.callbacks.DecoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
		return api.Continue
	}

	// only buffer the body if it is an HTTP connection
	if f.connection == HTTP {
		f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("Buffering request body data"))
		return api.StopAndBuffer
	}
	return api.Continue
}

func (f *filter) DecodeTrailers(trailerMap api.RequestTrailerMap) api.StatusType {
	return api.Continue
}

func (f *filter) EncodeHeaders(headerMap api.ResponseHeaderMap, endStream bool) api.StatusType {
	f.callbacks.Log(api.Debug, BuildLoggerMessage().str("f.connection", f.connection.String()).msg("EncodeHeaders enter"))
	if f.isInterruption {
		f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("Interruption already handled, sending downstream the local response"))
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
		f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("ProcessRequestBodyInPause3"))
		f.processRequestBody = true
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("Failed to process request body"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessRequestBody failed"))
			f.callbacks.EncoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
	}
	code, b := f.callbacks.StreamInfo().ResponseCode()
	if !b {
		code = 0
	}
	upgrade_websocket_header := false
	connection_upgrade_header := false
	headerMap.Range(func(key, value string) bool {
		// check for WS upgrade response
		if f.connection == UpgradeWebsocketRequested {
			if key == "upgrade" && strings.Contains(strings.ToLower(value), "websocket") {
				upgrade_websocket_header = true
			}
			if key == "connection" && strings.Contains(strings.ToLower(value), "upgrade") {
				connection_upgrade_header = true

			}
		}
		tx.AddResponseHeader(key, value)
		return true
	})
	if upgrade_websocket_header && connection_upgrade_header {
		f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("detected websocket upgrade response"))
		f.connection = WebsocketConnection
	}
	interruption := tx.ProcessResponseHeaders(int(code), f.httpProtocol)
	if interruption != nil {
		f.isInterruption = true
		f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessResponseHeader failed"))
		f.callbacks.EncoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}

	/* if this is not the end of the stream (i.e there is a body) and response
	 * body processing is enabled, we need to buffer the headers to avoid envoy
	 * already sending them downstream to the client before the body processing
	 * eventually changes the status code
	 */
	if !endStream && tx.IsResponseBodyAccessible() && f.connection == HTTP {
		f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("Buffering response headers"))
		return api.StopAndBuffer
	}

	return api.Continue
}

func (f *filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	f.callbacks.Log(api.Debug, BuildLoggerMessage().str("f.connection", f.connection.String()).msg("EncodeData enter"))

	// immediately return if its a websocket request as we can't handle the binary body data
	if f.connection == WebsocketConnection {
		f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("Skip response body processing because this is a websocket connection"))
		return api.Continue
	}
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
	f.callbacks.Log(api.Trace, BuildLoggerMessage().str("size", strconv.Itoa(bodySize)).msg("Processing incoming response data"))
	if !tx.IsResponseBodyAccessible() {
		f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("Skipping response body inspection, SecResponseBodyAccess is off"))
		if !f.withNoResponseBodyProcessed {
			// According to documentation, it is recommended to call this method even if it has no body.
			// It permits to execute rules belonging to request body phase, but not necesarily processing the response body.
			interruption, err := tx.ProcessResponseBody()
			f.withNoResponseBodyProcessed = true
			f.processResponseBody = true
			if err != nil {
				f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("ProcessResponseBody error"))
				return api.Continue
			}
			if interruption != nil {
				f.isInterruption = true
				f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessResponseBody forbidden"))
				f.callbacks.EncoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
				return api.LocalReply
			}
		}
		return api.Continue
	}
	if bodySize > 0 {
		ResponseBodyBuffer := buffer.Bytes()
		interruption, buffered, err := tx.WriteResponseBody(ResponseBodyBuffer)
		f.callbacks.Log(api.Trace, BuildLoggerMessage().str("size", strconv.Itoa(buffered)).msg("Buffered response data"))
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("Failed to write response body"))
			return api.Continue
		}
		/* WriteResponseBody triggers ProcessResponseBody if the bodylimit (SecResponseBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by response body processing.
		 */
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("WriteResponseBody interrupted"))
			f.callbacks.EncoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
	}
	if endStream {
		f.processResponseBody = true
		interruption, err := tx.ProcessResponseBody()
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("ProcessResponseBody error"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.processResponseBody = true
			buffer.Set(bytes.Repeat([]byte("\x00"), bodySize))
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("ProcessResponseBody failed"))
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
			f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("Running ProcessResponseBody in OnHttpStreamDone, triggered actions will not be enforced. Further logs are for detection only purposes"))
			f.processResponseBody = true
			_, err := tx.ProcessResponseBody()
			if err != nil {
				f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("Process response body onDestroy error"))
			}
		}
		f.tx.ProcessLogging()
		_ = f.tx.Close()
		f.callbacks.Log(api.Info, BuildLoggerMessage().msg("Finished"))
	}
}

func main() {
}
