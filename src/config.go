//  Copyright © 2023 Axkea, spacewander
//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

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
			logger:    BuildLoggerMessage(conf.logFormat),
		}
	}
}
