package common

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
	"gopkg.in/yaml.v2"
)

func ReadFiles(pattern string) ([]string, error) {

	ret := make([]string, 0)
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

func FilterStringMap(m map[string]string, keys []string) map[string]string {

	r := make(map[string]string)
	for k, v := range m {
		if len(keys) == 0 {
			r[k] = v
			continue
		}
		if utils.Contains(keys, k) {
			r[k] = v
		}
	}
	return r
}

func MergeStringMaps(maps ...map[string]string) map[string]string {

	r := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			r[k] = v
		}
	}
	return r
}

func MergeInterfacegMaps(maps ...map[string]interface{}) map[string]interface{} {

	r := make(map[string]interface{})
	for _, m := range maps {
		for k, v := range m {
			r[k] = v
		}
	}
	return r
}

func Md5(b []byte) []byte {
	h := md5.New()
	h.Write(b)
	return h.Sum(nil)
}

func Md5ToString(b []byte) string {

	hash := Md5(b)
	if hash != nil {
		return fmt.Sprintf("%x", hash)
	}
	return ""
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

func FileMd5ToString(path string) string {

	hash := FileMD5(path)
	if hash != nil {
		return fmt.Sprintf("%x", hash)
	}
	return ""
}

func IfDef(v, def interface{}) interface{} {
	if utils.IsEmpty(v) {
		return def
	}
	switch v := v.(type) {
	case string:
		if v == "" {
			return def
		}
	case int:
		if v == 0 {
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

func Render(def string, obj interface{}, observability *Observability) string {

	logger := observability.Logs()
	tpl, err := toolsRender.NewTextTemplate(toolsRender.TemplateOptions{Content: def}, observability)
	if err != nil {
		logger.Error(err)
		return def
	}

	s, err := RenderTemplate(tpl, def, obj)
	if err != nil {
		logger.Error(err)
		return def
	}
	return s
}

func GetStringKeys(arr map[string]string) []string {
	var keys []string
	for k := range arr {
		keys = append(keys, k)
	}
	return keys
}

func SortStringMapByKeys(m map[string]string, keys []string) map[string]string {

	r := make(map[string]string)
	for _, k := range keys {
		r[k] = m[k]
	}
	return r
}

func GetBaseConfigKeys(arr map[string]*BaseConfig) []string {
	var keys []string
	for k := range arr {
		keys = append(keys, k)
	}
	return keys
}

func GetFileKeys(arr map[string]*File) []string {
	var keys []string
	for k := range arr {
		keys = append(keys, k)
	}
	return keys
}

func GetLabelsKeys(arr map[string]Labels) []string {
	var keys []string
	for k := range arr {
		keys = append(keys, k)
	}
	return keys
}

func StringContainsAny(s string, arr []string) bool {

	for _, v := range arr {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

func ParsePeriodFromNow(period string, t time.Time) string {

	durStr := period
	if utils.IsEmpty(durStr) {
		return ""
	}

	if durStr == "" {
		durStr = "0s"
	}

	if durStr == "0d" {
		durStr = "0h"
	}

	dur, err := time.ParseDuration(durStr)
	if err != nil {
		return ""
	}

	from := t.Add(dur)
	return strconv.Itoa(int(from.Unix()))
}

func RemoveEmptyStrings(items []string) []string {

	r := make([]string, 0)

	for _, v := range items {
		if utils.IsEmpty(v) {
			continue
		}
		r = append(r, strings.TrimSpace(v))
	}

	return r
}

func ConvertLabelsMapToSinkMap(m LabelsMap) SinkMap {

	r := make(SinkMap)
	for k, v := range m {
		r[k] = v
	}
	return r
}

func ConvertSinkMapToLabelsMap(m SinkMap) LabelsMap {

	r := make(LabelsMap)
	for k, v := range m {
		s, ok := v.(Labels)
		if ok {
			r[k] = s
		}
	}
	return r
}

func ConvertObjectsToSinkMap(m Objects) SinkMap {

	r := make(SinkMap)
	for k, v := range m {
		r[k] = v
	}
	return r
}

func ConvertSinkMapToObjects(m SinkMap) Objects {

	r := make(Objects)
	for k, v := range m {
		s, ok := v.(*Object)
		if ok {
			r[k] = s
		}
	}
	return r
}

func MergeLabels(labels ...Labels) Labels {

	r := make(Labels)
	for _, l := range labels {
		for k, v := range l {
			if _, ok := r[k]; !ok {
				r[k] = v
			}
		}
	}
	return r
}

func StringSliceToMap(lines []string) map[string]string {
	l := make(map[string]string)
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			l[parts[0]] = parts[1]
		} else {
			l[parts[0]] = ""
		}
	}
	return l
}

func FileWriteWithCheckSum(path string, data []byte, checksum bool) (bool, error) {

	bytesHashString := Md5ToString(data)

	if checksum {

		if _, err := os.Stat(path); err == nil {
			fileHashString := ""
			fileHash := FileMD5(path)
			if fileHash != nil {
				fileHashString = fmt.Sprintf("%x", fileHash)
			}

			if fileHashString == bytesHashString {
				return true, nil
			}
		}
	}

	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return false, err
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		return false, err
	}
	return false, nil
}

func ReplaceLabelValues(labels Labels, replacements map[string]string) Labels {

	lbs := make(Labels)

	for k, v := range labels {
		for k2, v2 := range replacements {
			lbs[k] = strings.ReplaceAll(v, k2, v2)
		}
	}
	return lbs
}

func ReadJson(bytes []byte) (interface{}, error) {

	var v interface{}
	err := json.Unmarshal(bytes, &v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func ReadToml(bytes []byte) (interface{}, error) {

	var v interface{}
	err := toml.Unmarshal(bytes, &v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func ReadYaml(bytes []byte) (interface{}, error) {

	var v interface{}
	err := yaml.Unmarshal(bytes, &v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func ReadFile(path, typ string) (interface{}, error) {

	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	tp := strings.Replace(filepath.Ext(path), ".", "", 1)
	if typ != "" {
		tp = typ
	}

	var obj interface{}
	switch {
	case tp == "json":
		obj, err = ReadJson(bytes)
	case tp == "toml":
		obj, err = ReadToml(bytes)
	case (tp == "yaml") || (tp == "yml"):
		obj, err = ReadYaml(bytes)
	default:
		obj, err = ReadJson(bytes)
	}
	if err != nil {
		return nil, err
	}
	return obj, nil
}
