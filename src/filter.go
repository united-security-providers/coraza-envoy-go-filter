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

type RequestPhase int

const (
	PhaseUnknown RequestPhase = iota
	PhaseRequestHeader
	PhaseRequestBody
	PhaseResponseHeader
	PhaseResponseBody
)

func (p RequestPhase) String() string {
	switch p {
	case PhaseRequestHeader:
		return "request_header"
	case PhaseRequestBody:
		return "request_body"
	case PhaseResponseHeader:
		return "response_header"
	case PhaseResponseBody:
		return "response_body"
	default:
		return "unknown"
	}
}

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
	logger                      *BasicLogMessage
}

func (f *filter) DecodeHeaders(headerMap api.RequestHeaderMap, endStream bool) api.StatusType {
	f.connection = HTTP

	f.logDebug("DecodeHeaders enter", struct{ K, V string }{"f.connection", f.connection.String()})

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
		f.logInfo("Error getting x-request-id header")
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
			f.logInfo("Failed to parse server name from Host", struct{ K, V string }{"Host", host}, err)
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
		f.logInfo("RemotePort formatting error", err)
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	destIP, destPortString, _ := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamLocalAddress())
	destPort, err := strconv.Atoi(destPortString)
	if err != nil {
		f.logInfo("LocalPort formatting error", err)
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	tx.ProcessConnection(srcIP, srcPort, destIP, destPort)
	path := headerMap.Path()
	method := headerMap.Method()
	protocol, ok := f.callbacks.StreamInfo().Protocol()
	if !ok {
		f.logWarn("Protocol not set")
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
		f.logDebug("Websocket upgrade request detected")
		f.connection = UpgradeWebsocketRequested
	}
	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		f.handleInterruption(PhaseRequestHeader, interruption)
		return api.LocalReply
	}
	return api.Continue
}

func (f *filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	f.logDebug("DecodeData enter", struct{ K, V string }{"f.connection", f.connection.String()})

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
		f.logDebug("Skipping request body processing, SecRequestBodyAccess is off")
		f.processRequestBody = true
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			f.logInfo("Failed to process request body", err)
			return api.Continue
		}
		if interruption != nil {
			f.handleInterruption(PhaseRequestBody, interruption)
			return api.LocalReply
		}
		return api.Continue
	}
	bodySize := buffer.Len()
	f.logTrace("Processing incoming request data", struct{ K, V string }{"size", strconv.Itoa(bodySize)})
	if bodySize > 0 {
		bytes := buffer.Bytes()
		interruption, buffered, err := tx.WriteRequestBody(bytes)
		f.logTrace("Buffered request data", struct{ K, V string }{"size", strconv.Itoa(buffered)})
		if err != nil {
			f.logInfo("Failed to write request body", err)
			return api.Continue
		}

		/* WriteRequestBody triggers ProcessRequestBody if the bodylimit (SecRequestBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by request body processing.
		 */
		if interruption != nil {
			f.handleInterruption(PhaseRequestBody, interruption)
			return api.LocalReply
		}
	}
	if endStream {
		f.processRequestBody = true
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			f.logInfo("Failed to process request body", err)
			return api.Continue
		}
		if interruption != nil {
			f.handleInterruption(PhaseRequestBody, interruption)
			return api.LocalReply
		}
		return api.Continue
	}

	// only buffer the body if it is an HTTP connection
	if f.connection == HTTP {
		f.logDebug("Buffering request body data")
		return api.StopAndBuffer
	}
	return api.Continue
}

func (f *filter) DecodeTrailers(trailerMap api.RequestTrailerMap) api.StatusType {
	return api.Continue
}

func (f *filter) EncodeHeaders(headerMap api.ResponseHeaderMap, endStream bool) api.StatusType {
	f.logDebug("Encode headers enter", struct{ K, V string }{"f.connection", f.connection.String()})
	if f.isInterruption {
		f.logDebug("Interruption already handled, sending downstream the local response")
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
		f.logDebug("ProcessRequestBody in phase3")
		f.processRequestBody = true
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			f.logInfo("Failed to process request body", err)
			return api.Continue
		}
		if interruption != nil {
			f.handleInterruption(PhaseResponseHeader, interruption)
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
		f.logDebug("Websocket upgrade response detected")
		f.connection = WebsocketConnection
	}
	interruption := tx.ProcessResponseHeaders(int(code), f.httpProtocol)
	if interruption != nil {
		f.handleInterruption(PhaseResponseHeader, interruption)
		return api.LocalReply
	}

	/* if this is not the end of the stream (i.e there is a body) and response
	 * body processing is enabled, we need to buffer the headers to avoid envoy
	 * already sending them downstream to the client before the body processing
	 * eventually changes the status code
	 */
	if !endStream && tx.IsResponseBodyAccessible() && f.connection == HTTP {
		f.logDebug("Buffering response headers")
		return api.StopAndBuffer
	}

	return api.Continue
}

func (f *filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	f.logDebug("EncodeData enter", struct{ K, V string }{"f.connection", f.connection.String()})

	// immediately return if its a websocket request as we can't handle the binary body data
	if f.connection == WebsocketConnection {
		f.logDebug("Skip response body processing (websocket connection)")
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
	f.logTrace("Processing incoming response data", struct{ K, V string }{"size", strconv.Itoa(bodySize)})
	if !tx.IsResponseBodyAccessible() {
		f.logDebug("Skipping response body processing, SecResponseBodyAccess is off")
		if !f.withNoResponseBodyProcessed {
			// According to documentation, it is recommended to call this method even if it has no body.
			// It permits to execute rules belonging to request body phase, but not necesarily processing the response body.
			interruption, err := tx.ProcessResponseBody()
			f.withNoResponseBodyProcessed = true
			f.processResponseBody = true
			if err != nil {
				f.logInfo("Failed to process response body", err)
				return api.Continue
			}
			if interruption != nil {
				f.handleInterruption(PhaseResponseBody, interruption)
				return api.LocalReply
			}
		}
		return api.Continue
	}
	if bodySize > 0 {
		ResponseBodyBuffer := buffer.Bytes()
		interruption, buffered, err := tx.WriteResponseBody(ResponseBodyBuffer)
		f.logTrace("Buffered response body data", struct{ K, V string }{"size", strconv.Itoa(buffered)})
		if err != nil {
			f.logInfo("Failed to write response body", err)
			return api.Continue
		}
		/* WriteResponseBody triggers ProcessResponseBody if the bodylimit (SecResponseBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by response body processing.
		 */
		if interruption != nil {
			f.handleInterruption(PhaseResponseBody, interruption)
			return api.LocalReply
		}
	}
	if endStream {
		f.processResponseBody = true
		interruption, err := tx.ProcessResponseBody()
		if err != nil {
			f.logInfo("failed to process response body", err)
			return api.Continue
		}
		if interruption != nil {
			buffer.Set(bytes.Repeat([]byte("\x00"), bodySize))
			f.handleInterruption(PhaseResponseBody, interruption)
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
			f.logDebug("Running ProcessResponseBody in OnHttpStreamDone, triggered actions will not be enforced. Further logs are for detection only purposes")
			f.processResponseBody = true
			_, err := tx.ProcessResponseBody()
			if err != nil {
				f.logInfo("failed to process response body in OnDestroy", err)
			}
		}
		f.tx.ProcessLogging()
		_ = f.tx.Close()
		f.logInfo("Transaction finished")
	}
}

func (f *filter) handleInterruption(phase RequestPhase, interruption *types.Interruption) {
	f.isInterruption = true
	f.logInfo("Transaction interrupted",
		struct{ K, V string }{"phase", phase.String()},
		struct{ K, V string }{"ruleID", strconv.Itoa(interruption.RuleID)},
		struct{ K, V string }{"action", interruption.Action},
		struct{ K, V string }{"status", strconv.Itoa(interruption.Status)})

	switch phase {
	case PhaseRequestHeader, PhaseRequestBody:
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
	case PhaseResponseHeader, PhaseResponseBody:
		f.callbacks.EncoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
	}
}

/* helpers for easy logging */
func (f *filter) logTrace(parts ...interface{}) {
	f.callbacks.Log(api.Trace, f.logger.Log(parts...))
}
func (f *filter) logDebug(parts ...interface{}) {
	f.callbacks.Log(api.Debug, f.logger.Log(parts...))
}
func (f *filter) logInfo(parts ...interface{}) {
	f.callbacks.Log(api.Info, f.logger.Log(parts...))
}
func (f *filter) logWarn(parts ...interface{}) {
	f.callbacks.Log(api.Warn, f.logger.Log(parts...))
}
func (f *filter) logError(parts ...interface{}) {
	f.callbacks.Log(api.Error, f.logger.Log(parts...))
}
func (f *filter) logCritical(parts ...interface{}) {
	f.callbacks.Log(api.Critical, f.logger.Log(parts...))
}

func main() {
}
