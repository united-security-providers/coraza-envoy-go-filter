// Copyright © 2023 Axkea, spacewander
// Copyright © 2025 United Security Providers AG, Switzerland
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"google.golang.org/protobuf/types/known/anypb"

	"coraza-waf/internal/libinjection"
	"coraza-waf/internal/logging"
	"coraza-waf/internal/re2"
)

type Parser struct{}

type Configuration struct {
	directives       WafDirectives
	DefaultDirective string
	HostDirectiveMap HostDirectiveMap
	WafMaps          WafMaps
	LogFormat        logging.LogFormat
}

type WafMaps map[string]coraza.WAF

type WafDirectives map[string]Directives

type Directives struct {
	SimpleDirectives []string `json:"simple_directives"`
}

type HostDirectiveMap map[string]string

var filePathPrefix = regexp.MustCompile(".*/")
var maxMessageSize = 250
var logFormat = logging.FormatText

func (p Parser) Parse(any *anypb.Any, callbacks api.ConfigCallbackHandler) (any, error) {
	configStruct := &xds.TypedStruct{}
	if err := any.UnmarshalTo(configStruct); err != nil {
		return nil, err
	}
	v := configStruct.Value
	var config Configuration
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	if useRe2, ok := v.AsMap()["use_re2"].(bool); !ok || useRe2 {
		re2.Register()
	}

	if useLibinjection, ok := v.AsMap()["use_libinjection"].(bool); !ok || useLibinjection {
		libinjection.Register()
	}

	if directivesString, ok := v.AsMap()["directives"].(string); ok {
		var wafDirectives WafDirectives
		err := json.UnmarshalFromString(directivesString, &wafDirectives)
		if err != nil {
			return nil, err
		}
		if len(wafDirectives) == 0 {
			return nil, errors.New("directives is empty")
		}
		config.directives = wafDirectives

		// parse the WAFs into config.wafMaps in any case
		wafMaps := make(WafMaps)
		for wafName, wafRules := range config.directives {
			wafConfig := coraza.NewWAFConfig().WithErrorCallback(errorCallback).WithRootFS(root).WithDirectives(strings.Join(wafRules.SimpleDirectives, "\n"))
			waf, err := coraza.NewWAF(wafConfig)
			if err != nil {
				return nil, fmt.Errorf("%s mapping waf init error:%s", wafName, err.Error())
			}
			wafMaps[wafName] = waf
		}
		config.WafMaps = wafMaps
	} else {
		return nil, errors.New("directives does not exist")
	}
	if defaultDirectiveString, ok := v.AsMap()["default_directive"].(string); ok {
		_, ok := config.directives[defaultDirectiveString]
		if !ok {
			return nil, errors.New("the referenced default_directive does not exist in directives")
		}
		config.DefaultDirective = defaultDirectiveString
	} else {
		return nil, errors.New("default_directive does not exist")
	}

	// host_directives_map is not set, however we still need to initialize an empty host mapping
	if v.AsMap()["host_directive_map"] == nil {
		hostDirectiveMap := make(HostDirectiveMap)
		config.HostDirectiveMap = hostDirectiveMap

	} else {
		// try to read host_directives_map as JSON string
		if hostDirectiveMapString, ok := v.AsMap()["host_directive_map"].(string); ok {
			hostDirectiveMap := make(HostDirectiveMap)
			err := json.UnmarshalFromString(hostDirectiveMapString, &hostDirectiveMap)
			if err != nil {
				return nil, err
			}
			for host, rule := range hostDirectiveMap {
				_, ok := config.directives[rule]
				if !ok {
					return nil, fmt.Errorf("the referenced directive '%s' for host %s does not exist", rule, host)
				}
			}
			config.HostDirectiveMap = hostDirectiveMap
		} else {
			return nil, errors.New("host_directive_map is not a JSON string")
		}
	}

	logging.Init(logging.FormatText)
	logger := logging.GetLogger()
	// read log format
	if logFormatString, ok := v.AsMap()["log_format"].(string); ok {
		if strings.ToLower(logFormatString) == "plain" {
			logFormatString = logging.FormatText.String()
			logger.Warn("DEPRECATION: 'plain' has been changed to 'text'")
		}

		switch format := logging.LogFormat(strings.ToLower(logFormatString)); format {
		case logging.FormatJson, logging.FormatText, logging.FormatFtw:
			config.LogFormat = format
		default:
			return nil, fmt.Errorf("invalid log_format. Only '%s' and '%s' is supported", logging.FormatJson, logging.FormatText)
		}
	} else {
		config.LogFormat = logging.FormatText
		logger.Info("No log_format provided. Using default 'text'")
	}

	logFormat = config.LogFormat
	return &config, nil
}

func (p Parser) Merge(parentConfig any, childConfig any) any {
	panic("TODO")
}

func errorCallback(error ctypes.MatchedRule) {
	// FTW has its own log format because they expect the log to be formatted
	// in a specific way. Coraza already has a method that formats it correctly.

	if logFormat == logging.FormatFtw {
		msg := error.ErrorLog()
		switch error.Rule().Severity() {
		case ctypes.RuleSeverityEmergency, ctypes.RuleSeverityAlert, ctypes.RuleSeverityCritical:
			api.LogCritical(msg)
		case ctypes.RuleSeverityError:
			api.LogError(msg)
		case ctypes.RuleSeverityWarning:
			api.LogWarn(msg)
		case ctypes.RuleSeverityNotice, ctypes.RuleSeverityInfo, ctypes.RuleSeverityDebug:
			api.LogInfo(msg)
		default:
			// in case we don't have a rule severity make sure the rule appears in the logs by using error level
			api.LogError(msg)
		}
		return
	}

	// the transaction ID was set to the request ID on transaction initalization, see filter.go
	// see https://github.com/corazawaf/coraza/discussions/1186
	xReqID := error.TransactionID()
	category := ""

	if err := uuid.Validate(xReqID); err != nil {
		// the request ID was not available and coraza has choosen a random ID
		xReqID = ""
	}
	// determine category from configuration file information
	cfi := filePathPrefix.ReplaceAllString(error.Rule().File(), "")
	cfi = strings.ReplaceAll(cfi, ".conf", "")
	if cfi != "" {
		category = cfi
	}
	matchData := error.MatchedDatas()[0]
	rule := error.Rule()
	msg := matchData.Message()
	for _, md := range error.MatchedDatas() {
		if md.Message() != "" {
			msg = md.Message()
			break
		}
	}
	msg = "WAF rule triggered: " + msg
	if len(msg) > maxMessageSize {
		msg = msg[:maxMessageSize]
	}
	value := matchData.Value()
	if len(value) > maxMessageSize {
		value = value[:maxMessageSize]
	}
	data := matchData.Data()
	if len(data) > maxMessageSize {
		data = data[:maxMessageSize]
	}

	logger := logging.GetLogger().With(
		"tx", error.TransactionID(),
		"hostname", error.ServerIPAddress(),
		"uri", error.URI(),
		"client", error.ClientIPAddress(),
		"request_id", xReqID,
	)
	logger = logger.WithGroup("crs").With(
		"version", rule.Version(),
	)
	logger = logger.WithGroup("violated_rule").With(
		"id", strconv.Itoa(rule.ID()),
		"revision", rule.Revision(),
		"version", rule.Version(),
		"file", rule.File(),
		"line", strconv.Itoa(rule.Line()),
		"message", error.Message(),
		"data", data,
		"severity", rule.Severity().String(),
		"maturity", strconv.Itoa(rule.Maturity()),
		"accuracy", strconv.Itoa(rule.Accuracy()),
		"category", category,
		"tags", rule.Tags(),
	)

	logger = logger.WithGroup("match").With(
		"name", matchData.Variable().Name(),
		"key", matchData.Key(),
		"op", rule.Operator(),
		"value", value,
	)

	switch error.Rule().Severity() {
	case ctypes.RuleSeverityEmergency, ctypes.RuleSeverityAlert, ctypes.RuleSeverityCritical, ctypes.RuleSeverityError:
		logger.Error(msg)
	case ctypes.RuleSeverityWarning:
		logger.Warn(msg)
	case ctypes.RuleSeverityNotice, ctypes.RuleSeverityInfo, ctypes.RuleSeverityDebug:
		logger.Info(msg)
	default:
		// in case we don't have a rule severity make sure the rule appears in the logs by using error level
		logger.Error(msg)
	}
}
