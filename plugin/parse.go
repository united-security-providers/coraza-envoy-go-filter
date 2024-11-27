package main

import (
	"errors"
	"fmt"
	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
	jsoniter "github.com/json-iterator/go"
	"google.golang.org/protobuf/types/known/anypb"
	"strings"
)

func init() {
	http.RegisterHttpFilterFactoryAndConfigParser("waf-go-envoy", configFactory(), &parser{})
}

type parser struct {
}

type configuration struct {
	directives       WafDirectives
	defaultDirective string
	hostDirectiveMap HostDirectiveMap
	wafMaps          wafMaps
}

type wafMaps map[string]coraza.WAF

type WafDirectives map[string]Directives

type Directives struct {
	SimpleDirectives []string `json:"simple_directives"`
}

type HostDirectiveMap map[string]string

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
	} else {
		return nil, errors.New("directives is not exist")
	}
	if defaultDirectiveString, ok := v.AsMap()["default_directive"].(string); ok {
		_, ok := config.directives[defaultDirectiveString]
		if !ok {
			return nil, errors.New("default_directive is not exist")
		}
		config.defaultDirective = defaultDirectiveString
	} else {
		return nil, errors.New("default_directive is not exist")
	}

	if hostDirectiveMapString, ok := v.AsMap()["host_directive_map"].(string); ok {
		hostDirectiveMap := make(HostDirectiveMap)
		err := json.UnmarshalFromString(hostDirectiveMapString, &hostDirectiveMap)
		if err != nil {
			return nil, err
		}
		for host, rule := range hostDirectiveMap {
			_, ok := config.directives[rule]
			if !ok {
				return nil, errors.New(fmt.Sprintf("The rule corresponding to %s does not exist", host))
			}
		}
		config.hostDirectiveMap = hostDirectiveMap
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
	}
	return &config, nil
}

func (p parser) Merge(parentConfig interface{}, childConfig interface{}) interface{} {
	panic("TODO")
}

func errorCallback(error ctypes.MatchedRule) {
	msg := error.ErrorLog(error.Rule().ID())
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
