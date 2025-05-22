package main

import (
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

func configFactory() api.StreamFilterFactory {
	return func(c interface{}, callbacks api.FilterCallbackHandler) api.StreamFilter {
		conf, ok := c.(*configuration)
		if !ok {
			panic("unexpected config type")
		}
		return &filter{
			callbacks: callbacks,
			wafMaps:   conf.wafMaps,
			conf:      *conf,
		}
	}
}
