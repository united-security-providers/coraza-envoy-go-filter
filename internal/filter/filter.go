//  Copyright © 2023 Axkea, spacewander
//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package filter

import (
	"bytes"
	"coraza-waf/internal/config"
	"coraza-waf/internal/logger"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

const HOSTPOSTSEPARATOR string = ":"

type Filter struct {
	api.PassThroughStreamFilter

	Callbacks                          api.FilterCallbackHandler
	Config                             config.Configuration
	tx                                 types.Transaction
	wasInterrupted                     bool
	wasRequestBodyProcessed            bool
	wasResponseBodyProcessed           bool
	wasResponseBodyProcessedWithNoBody bool
	httpProtocol                       string
	connection                         connectionState
	Logger                             *logger.BasicLogMessage
}

func (f *Filter) DecodeHeaders(headerMap api.RequestHeaderMap, endStream bool) api.StatusType {
	f.connection = connectionStateHTTP
	host := headerMap.Host()
	if len(host) == 0 {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	// Initialize the WAF transaction
	err := f.initializeTx(headerMap, host)
	if err != nil {
		f.logError(err)
		return api.LocalReply
	}
	if f.tx.IsRuleEngineOff() {
		return api.Continue
	}
	// Process connection (will not block)
	srcIP, srcPort, err := f.splitHostPort(f.Callbacks.StreamInfo().DownstreamRemoteAddress())
	if err != nil {
		f.logError(err)
		return api.LocalReply
	}
	destIP, destPort, err := f.splitHostPort(f.Callbacks.StreamInfo().DownstreamLocalAddress())
	if err != nil {
		f.logError(err)
		return api.LocalReply
	}
	f.tx.ProcessConnection(srcIP, srcPort, destIP, destPort)
	// Process URI (will not block)
	path := headerMap.Path()
	method := headerMap.Method()
	protocol, ok := f.Callbacks.StreamInfo().Protocol()
	if !ok {
		f.logWarn("Protocol not set")
		protocol = "HTTP/2.0"
	}
	f.httpProtocol = protocol
	f.tx.ProcessURI(path, method, protocol)
	// Process request headers (might block)
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
		f.tx.AddRequestHeader(key, value)
		return true
	})
	if upgrade_websocket_header && connection_upgrade_header {
		f.logDebug("Websocket upgrade request detected")
		f.connection = connectionStateUpgradeWebsocketRequested
	}

	interruption := f.tx.ProcessRequestHeaders()
	if interruption != nil {
		f.handleInterruption(PhaseRequestHeader, interruption)
		return api.LocalReply
	}

	if endStream {
		err := f.validateRequestBody()
		if err != nil {
			f.logError(err)
			return api.LocalReply
		}
		return api.Continue
	}
	return api.StopAndBufferWatermark
}

func (f *Filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.wasInterrupted {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "interruption-already-handled")
		return api.LocalReply
	}
	if f.tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !f.tx.IsRequestBodyAccessible() {
		f.logDebug("Skipping request body processing, SecRequestBodyAccess is off")
		err := f.validateRequestBody()
		if err != nil {
			f.logError(err)
			return api.LocalReply
		}
		return api.Continue
	}
	f.logTrace("Processing incoming request data", struct{ K, V string }{"size", strconv.Itoa(buffer.Len())})
	if buffer.Len() > 0 {
		// Write request body into waf
		interruption, buffered, err := f.tx.WriteRequestBody(buffer.Bytes())
		f.logTrace("Buffered request data", struct{ K, V string }{"size", strconv.Itoa(buffered)})
		if err != nil {
			f.logError("Failed to write request body", err)
			/* processing error, block the request to prevent further processing */
			f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}

		/* WriteRequestBody triggers ProcessRequestBody if the bodylimit (SecRequestBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by request body processing.
		 */
		if interruption != nil {
			f.handleInterruption(PhaseRequestBody, interruption)
			return api.LocalReply
		}
	} else {
		f.logDebug("Empty request body, probably zero-length EOS")
		return api.Continue
	}
	// We reached the end of the body
	if endStream {
		f.wasRequestBodyProcessed = true
		err := f.validateRequestBody()
		if err != nil {
			f.logError(err)
			return api.LocalReply
		}
		return api.Continue
	}
	// only buffer the body if it is an HTTP connection
	if f.connection.IsHttp() {
		f.logDebug("Buffering request body data")
		return api.StopAndBuffer
	}
	return api.Continue
}

func (f *Filter) EncodeHeaders(headerMap api.ResponseHeaderMap, endStream bool) api.StatusType {
	if f.wasInterrupted {
		f.logDebug("Interruption already handled, sending downstream the local response")
		return api.Continue
	}
	// the nil check here MUST NEVER be removed
	// there are cases (e.g. malformed HTTP request) where envoy will automatically
	// jump from the decoding phase to the encoding phase
	if f.tx == nil || f.tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !f.wasRequestBodyProcessed {
		f.logDebug("ProcessRequestBody in phase3")
		f.wasRequestBodyProcessed = true
		interruption, err := f.tx.ProcessRequestBody()
		if err != nil {
			f.logError("Failed to process request body", err)
			/* processing error, block the request to prevent further processing */
			f.Callbacks.EncoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
		if interruption != nil {
			f.handleInterruption(PhaseResponseHeader, interruption)
			return api.LocalReply
		}
	}
	code, b := f.Callbacks.StreamInfo().ResponseCode()
	if !b {
		code = 0
	}
	// Process response headers (might block)
	upgrade_websocket_header := false
	connection_upgrade_header := false
	headerMap.Range(func(key, value string) bool {
		// check for WS upgrade response
		if f.connection.IsWebsocketUpgradeRequested() {
			if key == "upgrade" && strings.Contains(strings.ToLower(value), "websocket") {
				upgrade_websocket_header = true
			}
			if key == "connection" && strings.Contains(strings.ToLower(value), "upgrade") {
				connection_upgrade_header = true

			}
		}
		f.tx.AddResponseHeader(key, value)
		return true
	})
	if upgrade_websocket_header && connection_upgrade_header {
		f.logDebug("Websocket upgrade request detected")
		f.connection = connectionStateWebsocketConnection
	}
	interruption := f.tx.ProcessResponseHeaders(int(code), f.httpProtocol)
	if interruption != nil {
		f.handleInterruption(PhaseResponseHeader, interruption)
		return api.LocalReply
	}

	/* if this is not the end of the stream (i.e there is a body) and response
	 * body processing is enabled, we need to buffer the headers to avoid envoy
	 * already sending them downstream to the client before the body processing
	 * eventually changes the status code
	 */
	if !endStream && f.tx.IsResponseBodyAccessible() && f.connection.IsHttp() {
		f.logDebug("Buffering response headers")
		return api.StopAndBuffer
	}

	if endStream {
		err := f.validateResponseBody()
		if err != nil {
			f.logError(err)
			return api.LocalReply
		}
	}

	return api.Continue
}

func (f *Filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	// the nil check here MUST NEVER be removed
	// there are cases (e.g. malformed HTTP request) where envoy will automatically
	// jump from the decoding phase to the encoding phase
	if f.tx == nil || f.tx.IsRuleEngineOff() || f.connection.IsWebsocket() || f.wasResponseBodyProcessedWithNoBody {
		if f.connection.IsWebsocket() {
			f.logDebug("Skip response body processing (websocket connection)")
		}
		return api.Continue
	}
	if f.wasInterrupted {
		f.Callbacks.EncoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	f.logTrace("Processing incoming response data", struct{ K, V string }{"size", strconv.Itoa(buffer.Len())})
	if !f.tx.IsResponseBodyAccessible() {
		f.logDebug("Skipping response body processing, SecResponseBodyAccess is off")
		if !f.wasResponseBodyProcessedWithNoBody {
			f.wasResponseBodyProcessedWithNoBody = true
			f.wasResponseBodyProcessed = true
			err := f.validateResponseBody()
			if err != nil {
				f.logError(err)
				return api.LocalReply
			}
		}
		return api.Continue
	}
	if buffer.Len() > 0 {
		// Write response body into waf
		interruption, buffered, err := f.tx.WriteResponseBody(buffer.Bytes())
		f.logTrace("Buffered response body data", struct{ K, V string }{"size", strconv.Itoa(buffered)})
		if err != nil {
			f.logError("Failed to write response body", err)
			f.Callbacks.EncoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
		/* WriteResponseBody triggers ProcessResponseBody if the bodylimit (SecResponseBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by response body processing.
		 */
		if interruption != nil {
			f.handleInterruption(PhaseResponseBody, interruption)
			return api.LocalReply
		}
	}
	// We reached the end of the body
	if endStream {
		f.wasResponseBodyProcessed = true
		err := f.validateResponseBody()
		if err != nil {
			err := buffer.Set(bytes.Repeat([]byte("\x00"), buffer.Len()))
			if err != nil {
				f.logError("failed to write into internal buffer", err)
			}
			f.logError(err)
			return api.LocalReply
		}
	}

	return api.Continue
}

func (f *Filter) OnDestroy(reason api.DestroyReason) {
	if f.tx == nil {
		return
	}

	if !f.wasResponseBodyProcessed {
		f.logDebug("Running ProcessResponseBody in OnHttpStreamDone, triggered actions will not be enforced. Further logs are for detection only purposes")
		f.wasResponseBodyProcessed = true
		_, err := f.tx.ProcessResponseBody()
		if err != nil {
			f.logError("failed to process response body in OnDestroy", err)
		}
	}
	f.tx.ProcessLogging()
	_ = f.tx.Close()
	f.logInfo("Transaction finished")
}

func (f *Filter) initializeTx(headerMap api.RequestHeaderMap, host string) error {
	xReqId, exist := headerMap.Get("x-request-id")
	if !exist {
		f.logError("Error getting x-request-id header")
		xReqId = ""
	}
	waf := f.Config.WafMaps[f.Config.DefaultDirective]
	ruleName, ok := f.Config.HostDirectiveMap[host]
	if ok {
		waf = f.Config.WafMaps[ruleName]
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
			f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
			return fmt.Errorf("failed to parse server name from Host: %s", err)
		}
	}
	f.tx.SetServerName(server)

	return nil
}

func (f *Filter) validateRequestBody() error {
	interruption, err := f.tx.ProcessRequestBody()
	if err != nil {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "")
		return errors.New("failed to process request body")
	}
	if interruption != nil {
		f.handleInterruption(PhaseRequestBody, interruption)
		return errors.New("found interruption")
	}

	return nil
}

func (f *Filter) validateResponseBody() error {
	interruption, err := f.tx.ProcessResponseBody()
	if err != nil {
		f.Callbacks.EncoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "")
		return errors.New("failed to process response body")
	}
	if interruption != nil {
		f.handleInterruption(PhaseResponseBody, interruption)
		return errors.New("found interruption")
	}

	return nil
}

func (f *Filter) handleInterruption(phase phase, interruption *types.Interruption) {
	f.wasInterrupted = true
	f.logInfo("Transaction interrupted",
		struct{ K, V string }{"phase", phase.String()},
		struct{ K, V string }{"ruleID", strconv.Itoa(interruption.RuleID)},
		struct{ K, V string }{"action", interruption.Action},
		struct{ K, V string }{"status", strconv.Itoa(interruption.Status)})

	switch phase {
	case PhaseRequestHeader, PhaseRequestBody:
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
	case PhaseResponseHeader, PhaseResponseBody:
		f.Callbacks.EncoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
	}
}

func (f *Filter) splitHostPort(hostPortCombination string) (string, int, error) {
	ip, portString, err := net.SplitHostPort(hostPortCombination)
	if err != nil {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "")
		return "", 0, fmt.Errorf("address formatting err: %s", err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "")
		return "", 0, fmt.Errorf("port formatting err: %s", err)
	}

	return ip, port, nil
}

/* helpers for easy logging */
func (f *Filter) logTrace(parts ...interface{}) {
	f.Callbacks.Log(api.Trace, f.Logger.Log(parts...))
}
func (f *Filter) logDebug(parts ...interface{}) {
	f.Callbacks.Log(api.Debug, f.Logger.Log(parts...))
}
func (f *Filter) logInfo(parts ...interface{}) {
	f.Callbacks.Log(api.Info, f.Logger.Log(parts...))
}
func (f *Filter) logWarn(parts ...interface{}) {
	f.Callbacks.Log(api.Warn, f.Logger.Log(parts...))
}

//nolint:unused
func (f *Filter) logError(parts ...interface{}) {
	f.Callbacks.Log(api.Error, f.Logger.Log(parts...))
}

//nolint:unused
func (f *Filter) logCritical(parts ...interface{}) {
	f.Callbacks.Log(api.Critical, f.Logger.Log(parts...))
}
