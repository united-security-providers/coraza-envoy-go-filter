package main

import (
	"bytes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const HOSTPOSTSEPARATOR string = ":"

type filter struct {
	callbacks           api.FilterCallbackHandler
	proc_callbacks   api.FilterProcessCallbacks
	conf                configuration
	wafMaps             wafMaps
	tx                  types.Transaction
	httpProtocol        string
	isInterruption      bool
	processRequestBody  bool
	processResponseBody bool
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
	f.tx = waf.NewTransaction()
	f.tx.AddRequestHeader("Host", host)
	var server = host
	var err error
	if strings.Contains(host, HOSTPOSTSEPARATOR) {
		server, _, err = net.SplitHostPort(host)
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().str("Host", host).err(err).msg("Failed to parse server name from Host"))
			f.proc_callbacks.SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "Failed to parse server name from Host")
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
		f.proc_callbacks.SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "RemotePort formatting error")
		return api.LocalReply
	}
	destIP, destPortString, _ := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamLocalAddress())
	destPort, err := strconv.Atoi(destPortString)
	if err != nil {
		f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("LocalPort formatting error"))
		f.proc_callbacks.SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "LocalPort formatting error")
		return api.LocalReply
	}
	tx.ProcessConnection(srcIP, srcPort, destIP, destPort)
	path := headerMap.Path()
	method := headerMap.Method()
	protocol := headerMap.Scheme()
	//Maybe it's a bug? sometimes you can't get Protocol from Envoy
	if len(protocol) == 0 {
		f.callbacks.Log(api.Warn, BuildLoggerMessage().msg("Get protocol failed"))
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
		f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessRequestHeaders failed"))
		f.proc_callbacks.SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "Reject because of bad request header")
		return api.LocalReply
	}
	return api.Continue
}

func (f *filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.isInterruption {
		f.proc_callbacks.SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "Interruption already handled")
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
			f.proc_callbacks.SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "Reject because of bad request body")
			return api.LocalReply
		}
		return api.Continue
	}
	bodySize := buffer.Len()
	if bodySize > 0 {
		bytes := buffer.Bytes()
		interruption, _, err := tx.WriteRequestBody(bytes)
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("Failed to write request body"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("RequestBody is over limit"))
			f.proc_callbacks.SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "RequestBody is over limit")
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
			f.proc_callbacks.SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "ProcessRequestBody failed")
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
			f.proc_callbacks.SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "ProcessRequestBody failed")
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
		f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessResponseHeader failed"))
		f.proc_callbacks.SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "Reject because of bad response header")
		return api.LocalReply
	}
	return api.Continue
}

func (f *filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	if f.isInterruption {
		f.proc_callbacks.SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "Interruption already handled")
		return api.LocalReply
	}
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	bodySize := buffer.Len()
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !tx.IsResponseBodyAccessible() {
		f.callbacks.Log(api.Debug, BuildLoggerMessage().msg("Skipping response body inspection, SecResponseBodyAccess is off"))
		if !f.processResponseBody {
			interruption, err := tx.ProcessResponseBody()
			if err != nil {
				f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("ProcessResponseBody error"))
				return api.Continue
			}
			f.processResponseBody = true
			if interruption != nil {
				f.isInterruption = true
				f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ProcessResponseBody forbidden"))
				f.proc_callbacks.SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "ProcessResponseBody forbidden")
				return api.LocalReply
			}
		}
	}
	if bodySize > 0 {
		ResponseBodyBuffer := buffer.Bytes()
		interruption, _, err := tx.WriteResponseBody(ResponseBodyBuffer)
		if err != nil {
			f.callbacks.Log(api.Info, BuildLoggerMessage().err(err).msg("Failed to write response body"))
			return api.Continue
		}
		if interruption != nil {
			f.isInterruption = true
			f.callbacks.Log(api.Info, BuildLoggerMessage().msg("ResponseBody is over limit"))
			f.proc_callbacks.SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "ResponseBody is over limit")
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
			f.proc_callbacks.SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "Reject because of bad response body")
			return api.LocalReply
		}
		return api.Continue
	}
	return api.StopAndBuffer
}

func (f *filter) EncodeTrailers(trailerMap api.ResponseTrailerMap) api.StatusType {
	return api.Continue
}

func (f *filter) OnLog(api.RequestHeaderMap, api.RequestTrailerMap, api.ResponseHeaderMap, api.ResponseTrailerMap) {}
func (f *filter) OnLogDownstreamPeriodic(api.RequestHeaderMap, api.RequestTrailerMap, api.ResponseHeaderMap, api.ResponseTrailerMap) {}
func (f *filter) OnLogDownstreamStart(api.RequestHeaderMap) {}
func (f *filter) OnStreamComplete() {}

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
