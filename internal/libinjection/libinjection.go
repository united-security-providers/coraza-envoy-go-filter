//go:build libinjection_cgo

package libinjection

import "github.com/corazawaf/coraza-wasilibs"

func Register() {
	wasilibs.RegisterSQLi()
	wasilibs.RegisterXSS()
}
