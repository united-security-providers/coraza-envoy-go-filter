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
			"@coraza-setup": "coraza.conf",    // configures rule engine for coraza
			"@crs-setup":    "crs-setup.conf", // configures coreruleset
			// TODO: remove these from release-builds?  (via buildflag?)
			"@crs-ftw":    "crs-ftw.conf",    // configures coreruleset for ftw tests
			"@coraza-ftw": "coraza-ftw.conf", // configures coraza for ftw tests
		},
		map[string]string{
			"@owasp_crs": "rules", // crs rules
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
