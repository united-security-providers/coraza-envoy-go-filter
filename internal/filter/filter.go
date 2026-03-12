// Copyright © 2023 Axkea, spacewander
// Copyright © 2025 United Security Providers AG, Switzerland
// SPDX-License-Identifier: Apache-2.0

package filter

import (
	"bytes"
	"coraza-waf/internal/config"
	"coraza-waf/internal/logging"
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

	Callbacks      api.FilterCallbackHandler
	Config         config.Configuration
	tx             types.Transaction
	wasInterrupted bool
	httpProtocol   string
	connection     connectionState
	requestId      string
}

func (f *Filter) DecodeHeaders(headerMap api.RequestHeaderMap, endStream bool) api.StatusType {
	logger := logging.GetLogger().With("action", "DecodeHeaders")
	requestId, exist := headerMap.Get("x-request-id")
	if !exist {
		logger.Debug("x-request-id header missing")
		requestId = "<unknown>"
	}
	f.requestId = requestId
	logger = logger.With("request-id", requestId)
	f.connection = connectionStateHttp
	host := headerMap.Host()
	if len(host) == 0 {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	// Initialize the WAF transaction
	err := f.initializeTx(logger, headerMap, host)
	if err != nil {
		logger.Error("could not initialize transaction", "error", err.Error())
		return api.LocalReply
	}
	if f.tx.IsRuleEngineOff() {
		return api.Continue
	}
	// Process connection (will not block)
	srcIP, srcPort, err := f.splitHostPort(f.Callbacks.StreamInfo().DownstreamRemoteAddress())
	if err != nil {
		logger.Error("could not parse IP and port for remote address", "error", err.Error())
		return api.LocalReply
	}
	destIP, destPort, err := f.splitHostPort(f.Callbacks.StreamInfo().DownstreamLocalAddress())
	if err != nil {
		logger.Error("could not parse IP and port for local address", "error", err.Error())
		return api.LocalReply
	}
	f.tx.ProcessConnection(srcIP, srcPort, destIP, destPort)
	// Process URI (will not block)
	path := headerMap.Path()
	method := headerMap.Method()
	if strings.EqualFold(method, "connect") {
		f.connection = connectionStateHttpTunnel
	}
	protocol, ok := f.Callbacks.StreamInfo().Protocol()
	if !ok {
		logger.Warn("Protocol not set")
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
		logger.Debug("Websocket upgrade request detected")
		f.connection = connectionStateUpgradeWebsocketRequested
	}

	interruption := f.tx.ProcessRequestHeaders()
	if interruption != nil {
		f.handleInterruption(logger, PhaseRequestHeader, interruption)
		return api.LocalReply
	}

	if endStream {
		err := f.validateRequestBody(logger)
		if err != nil {
			logger.Error("request validation failed", "error", err.Error())
			return api.LocalReply
		}
		return api.Continue
	}

	if f.tx.IsRequestBodyAccessible() && f.connection.IsHttp() {
		logger.Debug("Buffering request body data")
		return api.StopAndBuffer
	}

	return api.StopAndBufferWatermark
}

func (f *Filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	logger := logging.GetLogger().With("action", "DecodeData").With("request-id", f.requestId)
	if f.wasInterrupted {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "interruption-already-handled")
		return api.LocalReply
	}
	if f.tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !f.tx.IsRequestBodyAccessible() {
		logger.Debug("Skipping request body processing, SecRequestBodyAccess is off")
		err := f.validateRequestBody(logger)
		if err != nil {
			logger.Error("request validation failed", "error", err.Error())
			return api.LocalReply
		}
		return api.Continue
	}
	logger.Debug("Processing incoming request data", "size", buffer.Len())
	if buffer.Len() > 0 {
		// Write request body into waf
		interruption, buffered, err := f.tx.WriteRequestBody(buffer.Bytes())
		logger.Debug("Buffered request data", "size", buffered)
		if err != nil {
			logger.Error("Failed to write request body", "error", err)
			/* processing error, block the request to prevent further processing */
			f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
		/* WriteRequestBody triggers ProcessRequestBody if the bodylimit (SecRequestBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by request body processing.
		 */
		if interruption != nil {
			f.handleInterruption(logger, PhaseRequestBody, interruption)
			return api.LocalReply
		}
	}

	if endStream {
		err := f.validateRequestBody(logger)
		if err != nil {
			logger.Error("request validation failed", "error", err.Error())
			return api.LocalReply
		}
	}
	return api.Continue
}

func (f *Filter) EncodeHeaders(headerMap api.ResponseHeaderMap, endStream bool) api.StatusType {
	logger := logging.GetLogger().With("action", "EncodeHeaders")
	if f.wasInterrupted {
		logger.Debug("Interruption already handled, sending downstream the local response")
		return api.Continue
	}
	// the nil check here MUST NEVER be removed
	// there are cases (e.g. malformed HTTP request) where envoy will automatically
	// jump from the decoding phase to the encoding phase
	if f.tx == nil || f.tx.IsRuleEngineOff() {
		return api.Continue
	}
	logger = logger.With("request-id", f.requestId)
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
		logger.Debug("Websocket upgrade request detected")
		f.connection = connectionStateWebsocketConnection
	}
	interruption := f.tx.ProcessResponseHeaders(int(code), f.httpProtocol)
	if interruption != nil {
		f.handleInterruption(logger, PhaseResponseHeader, interruption)
		return api.LocalReply
	}

	if endStream {
		err := f.validateResponseBody(logger)
		if err != nil {
			logger.Error("response validation failed", "error", err.Error())
			return api.LocalReply
		}
		return api.Continue
	}

	if f.tx.IsResponseBodyAccessible() && f.connection.IsHttp() {
		logger.Debug("Buffering response headers")
		return api.StopAndBuffer
	}

	return api.StopAndBufferWatermark
}

func (f *Filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	logger := logging.GetLogger().With("action", "EncodeData").With("request-id", f.requestId)
	// the nil check here MUST NEVER be removed
	// there are cases (e.g. malformed HTTP request) where envoy will automatically
	// jump from the decoding phase to the encoding phase
	if f.tx == nil || f.tx.IsRuleEngineOff() || f.connection.IsWebsocket() {
		if f.connection.IsWebsocket() {
			logger.Debug("Skip response body processing (websocket connection)")
		}
		return api.Continue
	}
	if f.wasInterrupted {
		f.Callbacks.EncoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	logger.Debug("Processing incoming response data", "size", buffer.Len())
	if !f.tx.IsResponseBodyAccessible() {
		logger.Debug("Skipping response body processing, SecResponseBodyAccess is off")
		err := f.validateResponseBody(logger)
		if err != nil {
			logger.Error("response validation failed", "error", err.Error())
			return api.LocalReply
		}
		return api.Continue
	}
	if buffer.Len() > 0 {
		// Write response body into waf
		interruption, buffered, err := f.tx.WriteResponseBody(buffer.Bytes())
		logger.Debug("Buffered response body data", "size", buffered)
		if err != nil {
			logger.Error("Failed to write response body", "error", err)
			f.Callbacks.EncoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
		/* WriteResponseBody triggers ProcessResponseBody if the bodylimit (SecResponseBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by response body processing.
		 */
		if interruption != nil {
			f.handleInterruption(logger, PhaseResponseBody, interruption)
			return api.LocalReply
		}
	}
	// We reached the end of the body
	if endStream {
		err := f.validateResponseBody(logger)
		if err != nil {
			err := buffer.Set(bytes.Repeat([]byte("\x00"), buffer.Len()))
			if err != nil {
				logger.Error("failed to write into internal buffer", "error", err)
			}
			logger.Error("response validation failed", "error", err.Error())
			return api.LocalReply
		}
	}

	return api.Continue
}

func (f *Filter) OnDestroy(reason api.DestroyReason) {
	logger := logging.GetLogger().With("action", "OnDestroy").With("request-id", f.requestId)
	if f.tx == nil {
		return
	}

	f.tx.ProcessLogging()
	_ = f.tx.Close()
	logger.Info("Transaction finished")
}

func (f *Filter) initializeTx(logger logging.Logger, headerMap api.RequestHeaderMap, host string) error {
	xReqId, exist := headerMap.Get("x-request-id")
	if !exist {
		logger.Error("Error getting x-request-id header")
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
		server, _, err = f.splitHostPort(host)
		if err != nil {
			f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
			return fmt.Errorf("failed to parse server name from Host: %s", err)
		}
	}
	f.tx.SetServerName(server)

	return nil
}

func (f *Filter) validateRequestBody(logger logging.Logger) error {
	interruption, err := f.tx.ProcessRequestBody()
	if err != nil {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "")
		return errors.New("failed to process request body")
	}
	if interruption != nil {
		f.handleInterruption(logger, PhaseRequestBody, interruption)
		return errors.New("found interruption")
	}

	return nil
}

func (f *Filter) validateResponseBody(logger logging.Logger) error {
	interruption, err := f.tx.ProcessResponseBody()
	if err != nil {
		f.Callbacks.EncoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "")
		return errors.New("failed to process response body")
	}
	if interruption != nil {
		f.handleInterruption(logger, PhaseResponseBody, interruption)
		return errors.New("found interruption")
	}

	return nil
}

func (f *Filter) handleInterruption(logger logging.Logger, phase phase, interruption *types.Interruption) {
	f.wasInterrupted = true
	logger.Info(
		"Transaction interrupted",
		"phase", phase.String(),
		"ruleID", interruption.RuleID,
		"action", interruption.Action,
		"status", interruption.Status,
	)

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
