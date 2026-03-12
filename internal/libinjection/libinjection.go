// Copyright © 2026 United Security Providers AG, Switzerland
// SPDX-License-Identifier: Apache-2.0

//go:build libinjection_cgo

package libinjection

import "github.com/corazawaf/coraza-wasilibs"

func Register() {
	wasilibs.RegisterSQLi()
	wasilibs.RegisterXSS()
}
