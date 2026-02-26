package main

import (
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"

	"coraza-waf/internal/config"
	"coraza-waf/internal/filter"
	"coraza-waf/internal/logger"
)

const PluginName = "coraza-waf"

func filterFactory(c any, callbacks api.FilterCallbackHandler) api.StreamFilter {
	config, ok := c.(*config.Configuration)
	if !ok {
		panic("unexpected config type")
	}
	return &filter.Filter{
		Callbacks: callbacks,
		Config:    *config,
		Logger:    logger.BuildLoggerMessage(config.LogFormat),
	}
}

func init() {
	http.RegisterHttpFilterFactoryAndConfigParser(PluginName, filterFactory, &config.Parser{})
}

func main() {}
