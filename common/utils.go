package common

import (
	"crypto/md5"
	"io"
	"os"
	"path/filepath"
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
