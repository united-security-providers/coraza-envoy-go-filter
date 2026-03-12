// Copyright © 2026 United Security Providers AG, Switzerland
// SPDX-License-Identifier: Apache-2.0

//go:build re2_cgo

package re2

import "github.com/corazawaf/coraza-wasilibs"

func Register() {
	wasilibs.RegisterRX()
}
