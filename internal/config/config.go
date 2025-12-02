//  Copyright © 2023 Axkea, spacewander
//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"google.golang.org/protobuf/types/known/anypb"

	"coraza-waf/internal/libinjection"
	"coraza-waf/internal/logger"
	"coraza-waf/internal/re2"
)

type Parser struct{}

type Configuration struct {
	directives       WafDirectives
	DefaultDirective string
	HostDirectiveMap HostDirectiveMap
	WafMaps          WafMaps
	LogFormat        string
}

type WafMaps map[string]coraza.WAF

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

func (p Parser) Parse(any *anypb.Any, callbacks api.ConfigCallbackHandler) (interface{}, error) {
	configStruct := &xds.TypedStruct{}
	if err := any.UnmarshalTo(configStruct); err != nil {
		return nil, err
	}
	v := configStruct.Value
	var config Configuration
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
		wafMaps := make(WafMaps)
		for wafName, wafRules := range config.directives {
			wafConfig := coraza.NewWAFConfig().WithErrorCallback(errorCallback).WithRootFS(root).WithDirectives(strings.Join(wafRules.SimpleDirectives, "\n"))
			waf, err := coraza.NewWAF(wafConfig)
			if err != nil {
				return nil, errors.New(fmt.Sprintf("%s mapping waf init error:%s", wafName, err.Error()))
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
					return nil, errors.New(fmt.Sprintf("the referenced directive '%s' for host %s does not exist", rule, host))
				}
			}
			config.HostDirectiveMap = hostDirectiveMap
		} else {
			return nil, errors.New("host_directive_map is not a JSON string")
		}
	}

	// read log format
	if logFormatString, ok := v.AsMap()["log_format"].(string); ok {
		if strings.ToLower(logFormatString) == "json" || strings.ToLower(logFormatString) == "plain" {
			config.LogFormat = strings.ToLower(logFormatString)
			logFormat = strings.ToLower(logFormatString)
		} else {
			return nil, errors.New("Invalid log_format. Only 'json' and 'plain' is supported")
		}
	} else {
		config.LogFormat = "plain"
		logFormat = "plain"
		api.LogInfo(logger.BuildLoggerMessage(logFormat).Log("No log_format provided. Using default 'plain'"))
	}

	if useRe2, ok := v.AsMap()["useRe2"].(bool); !ok || useRe2 {
		re2.Register()
	}

	if useLibinjection, ok := v.AsMap()["useLibinjection"].(bool); !ok || useLibinjection {
		libinjection.Register()
	}

	return &config, nil
}

func (p Parser) Merge(parentConfig interface{}, childConfig interface{}) interface{} {
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
		msg = error.ErrorLog()
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
