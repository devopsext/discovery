package common

import (
	"crypto/md5"
	"io"
	"os"
	"path/filepath"
	"strings"

	toolsRender "github.com/devopsext/tools/render"
)

func ReadFiles(pattern string) ([]string, error) {

	ret := []string{}
	err := filepath.Walk(pattern, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ret = append(ret, path)
		}
		return nil
	})
	return ret, err
}

func MergeMaps(maps ...map[string]string) map[string]string {

	r := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			r[k] = v
		}
	}
	return r
}

func ByteMD5(b []byte) []byte {
	h := md5.New()
	h.Write(b)
	return h.Sum(nil)
}

func FileMD5(path string) []byte {

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil
	}
	return h.Sum(nil)
}

func IfDef(v, def interface{}) interface{} {
	if v == nil {
		return def
	}
	switch v.(type) {
	case string:
		if v.(string) == "" {
			return def
		}
	case int:
		if v.(int) == 0 {
			return def
		}
	}
	return v
}

func StringInArr(a string, arr []string) bool {
	for _, b := range arr {
		if b == a {
			return true
		}
	}
	return false
}

func RenderTemplate(tpl *toolsRender.TextTemplate, def string, obj interface{}) (string, error) {

	if tpl == nil {
		return def, nil
	}

	b, err := tpl.RenderObject(obj)
	if err != nil {
		return def, err
	}
	r := strings.TrimSpace(string(b))
	// simplify <no value> => empty string
	return strings.ReplaceAll(r, "<no value>", ""), nil
}
