//  Copyright © 2023 Axkea, spacewander
//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"google.golang.org/protobuf/types/known/anypb"
)

func init() {
	http.RegisterHttpFilterFactoryAndConfigParser("coraza-waf", configFactory(), &parser{})
}

type parser struct {
}

type configuration struct {
	directives       WafDirectives
	defaultDirective string
	hostDirectiveMap HostDirectiveMap
	wafMaps          wafMaps
	logFormat        string
}

type wafMaps map[string]coraza.WAF

type WafDirectives map[string]Directives

type Directives struct {
	SimpleDirectives []string `json:"simple_directives"`
}

type HostDirectiveMap map[string]string

type JSONRuleLogEntry struct {
	RuleID          int      `json:"id"`
	Category        string   `json:"category"`
	Severity        string   `json:"severity"`
	Data            string   `json:"data"`
	Message         string   `json:"message"`
	MatchedData     string   `json:"matched_data"`
	MatchedDataName string   `json:"matched_data_name"`
	Tags            []string `json:"tags"`
}

type JSONErrorLogLine struct {
	Url            string           `json:"request.path"`
	Rule           JSONRuleLogEntry `json:"crs.violated_rule"`
	ClientIP       string           `json:"client.address"`
	TransactionID  string           `json:"transaction.id"`
	RuleSetVersion string           `json:"crs.version"`
	RequestID      string           `json:"request.id"`
}

var filePathPrefix = regexp.MustCompile(".*/")
var logFormat string

func (p parser) Parse(any *anypb.Any, callbacks api.ConfigCallbackHandler) (interface{}, error) {
	configStruct := &xds.TypedStruct{}
	if err := any.UnmarshalTo(configStruct); err != nil {
		return nil, err
	}
	v := configStruct.Value
	var config configuration
	json := jsoniter.ConfigCompatibleWithStandardLibrary
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
		wafMaps := make(wafMaps)
		for wafName, wafRules := range config.directives {
			wafConfig := coraza.NewWAFConfig().WithErrorCallback(errorCallback).WithRootFS(root).WithDirectives(strings.Join(wafRules.SimpleDirectives, "\n"))
			waf, err := coraza.NewWAF(wafConfig)
			if err != nil {
				return nil, errors.New(fmt.Sprintf("%s mapping waf init error:%s", wafName, err.Error()))
			}
			wafMaps[wafName] = waf
		}
		config.wafMaps = wafMaps
	} else {
		return nil, errors.New("directives does not exist")
	}
	if defaultDirectiveString, ok := v.AsMap()["default_directive"].(string); ok {
		_, ok := config.directives[defaultDirectiveString]
		if !ok {
			return nil, errors.New("the referenced default_directive does not exist in directives")
		}
		config.defaultDirective = defaultDirectiveString
	} else {
		return nil, errors.New("default_directive does not exist")
	}

	// host_directives_map is not set, however we still need to initialize an empty host mapping
	if v.AsMap()["host_directive_map"] == nil {
		hostDirectiveMap := make(HostDirectiveMap)
		config.hostDirectiveMap = hostDirectiveMap

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
					return nil, errors.New(fmt.Sprintf("the referenced directive '%s' for host %s does not exist", rule, host))
				}
			}
			config.hostDirectiveMap = hostDirectiveMap
		} else {
			return nil, errors.New("host_directive_map is not a JSON string")
		}
	}

	// read log format
	if logFormatString, ok := v.AsMap()["log_format"].(string); ok {
		if strings.ToLower(logFormatString) == "json" || strings.ToLower(logFormatString) == "plain" {
			config.logFormat = strings.ToLower(logFormatString)
			logFormat = strings.ToLower(logFormatString)
		} else {
			return nil, errors.New("Invalid log_format. Only 'json' and 'plain' is supported")
		}
	} else {
		config.logFormat = "plain"
		logFormat = "plain"
		api.LogInfo(BuildLoggerMessage().msg("No log_format provided. Using default 'plain'"))
	}

	return &config, nil
}

func (p parser) Merge(parentConfig interface{}, childConfig interface{}) interface{} {
	panic("TODO")
}

func errorCallback(error ctypes.MatchedRule) {
	var msg string

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

	if logFormat == "json" {
		line := JSONErrorLogLine{
			TransactionID:  error.TransactionID(),
			RuleSetVersion: error.Rule().Version(),
			Url:            error.URI(),
			Rule: JSONRuleLogEntry{
				RuleID:          error.Rule().ID(),
				Category:        category,
				Severity:        strings.ToUpper(error.Rule().Severity().String()),
				Data:            error.Data(),
				Message:         error.Message(),
				MatchedData:     error.MatchedDatas()[0].Variable().Name(),
				MatchedDataName: error.MatchedDatas()[0].Key(),
				Tags:            error.Rule().Tags(),
			},
			ClientIP:  error.ClientIPAddress(),
			RequestID: xReqID,
		}
		bytes, _ := json.Marshal(line)
		msg = string(bytes)
	} else {
		msg = BuildLoggerMessage().
			str("client_ip", error.ClientIPAddress()).
			str("uri", error.URI()).
			str("transaction_id", error.TransactionID()).
			str("rule_id", strconv.Itoa(error.Rule().ID())).
			str("category", category).
			str("severity", strings.ToUpper(error.Rule().Severity().String())).
			str("data", error.Data()).
			str("message", error.Message()).
			str("matched_data", error.MatchedDatas()[0].Variable().Name()).
			str("matched_data_name", error.MatchedDatas()[0].Key()).
			str("tags", strings.Join(error.Rule().Tags(), ", ")).
			str("crs_version", error.Rule().Version()).
			str("request_id", xReqID).
			msg("")

	}

	switch error.Rule().Severity() {
	case ctypes.RuleSeverityEmergency:
		api.LogCritical(msg)
	case ctypes.RuleSeverityAlert:
		api.LogCritical(msg)
	case ctypes.RuleSeverityCritical:
		api.LogCritical(msg)
	case ctypes.RuleSeverityError:
		api.LogError(msg)
	case ctypes.RuleSeverityWarning:
		api.LogWarn(msg)
	case ctypes.RuleSeverityNotice:
		api.LogInfo(msg)
	case ctypes.RuleSeverityInfo:
		api.LogInfo(msg)
	case ctypes.RuleSeverityDebug:
		api.LogInfo(msg)
	}
}
