//go:build re2_cgo

package re2

import "github.com/corazawaf/coraza-wasilibs"

func Register() {
	wasilibs.RegisterRX()
}
