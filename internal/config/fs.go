// Copyright © 2023 Axkea, spacewander
// Copyright © 2025 United Security Providers AG, Switzerland
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

var (
	//go:embed coreruleset
	crs  embed.FS
	root fs.FS
)

func init() {
	crsFS, err := fs.Sub(crs, "coreruleset")
	if err != nil {
		panic(err)
	}
	root = &rulesFS{
		crsFS,
		map[string]string{
			// LTS
			"@coraza-lts":    "lts/coraza.conf",    // configures rule engine for coraza
			"@crs-setup-lts": "lts/crs-setup.conf", // configures coreruleset
			// LATEST
			"@coraza-latest":    "latest/coraza.conf",    // configures rule engine for coraza
			"@crs-setup-latest": "latest/crs-setup.conf", // configures coreruleset
			// FTW
			// TODO: remove these from release-builds?  (via buildflag?)
			"@crs-ftw-lts":       "lts/crs-ftw.conf",       // configures lts coreruleset for ftw tests
			"@coraza-ftw-lts":    "lts/coraza-ftw.conf",    // configures coraza for ftw tests
			"@crs-ftw-latest":    "latest/crs-ftw.conf",    // configures latest coreruleset for ftw tests
			"@coraza-ftw-latest": "latest/coraza-ftw.conf", // configures coraza for ftw tests
		},
		map[string]string{
			"@owasp_crs_lts":    "lts/rules",    // lts rules
			"@owasp_crs_latest": "latest/rules", // latest rules
		},
	}
}

type rulesFS struct {
	fs           fs.FS
	filesMapping map[string]string
	dirsMapping  map[string]string
}

func (r rulesFS) Open(name string) (fs.File, error) {
	if strings.HasPrefix(name, "@") {
		return r.fs.Open(r.mapPath(name))
	}
	return os.Open(name)

}

func (r rulesFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !strings.HasPrefix(name, "@") {
		return os.ReadDir(name)
	}
	for a, dst := range r.dirsMapping {
		if a == name {
			return fs.ReadDir(r.fs, dst)
		}

		prefix := a + "/"
		if strings.HasPrefix(name, prefix) {
			return fs.ReadDir(r.fs, fmt.Sprintf("%s/%s", dst, name[len(prefix):]))
		}
	}
	return fs.ReadDir(r.fs, name)
}

func (r rulesFS) ReadFile(name string) ([]byte, error) {
	if strings.HasPrefix(name, "@") {
		return fs.ReadFile(r.fs, r.mapPath(name))
	}
	return os.ReadFile(name)
}

func (r rulesFS) mapPath(p string) string {
	if strings.IndexByte(p, '/') != -1 {
		// is not in root, hence we can do dir mapping
		for a, dst := range r.dirsMapping {
			prefix := a + "/"
			if strings.HasPrefix(p, prefix) {
				return fmt.Sprintf("%s/%s", dst, p[len(prefix):])
			}
		}
	}

	for a, dst := range r.filesMapping {
		if a == p {
			return dst
		}
	}

	return p
}
