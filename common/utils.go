package common

import (
	"crypto/md5"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
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

	if utils.IsEmpty(v) {
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

	from := t.Add(time.Duration(dur))
	return strconv.Itoa(int(from.Unix()))
}

func parseURL(s string, defSchema string) (*url.URL, error) {

	schema := defSchema
	rest := s

	arr := strings.Split(s, "://")

	if len(arr) == 2 {
		s1 := strings.TrimSpace(arr[0])
		if !utils.IsEmpty(s1) {
			schema = s1
		}
		rest = strings.TrimSpace(arr[1])
	}

	u, err := url.Parse(fmt.Sprintf("%s://%s", schema, rest))
	if err != nil {
		return nil, err
	}
	return u, nil
}

// prometheus=prometheus.service.svc:9090, victoria=https://user:pass@victoria.some.where, source2=http://prometheus.location
func GetPrometheusDiscoveriesByInstances(names string, logger sreCommon.Logger) []PromDiscoveryObject {

	nameItems := RemoveEmptyStrings(strings.Split(names, ","))
	var promDiscoveryObjects []PromDiscoveryObject

	for index, item := range nameItems {

		var name, nurl string
		parts := strings.SplitN(item, "=", 2)
		if len(parts) == 2 {
			name = strings.TrimSpace(parts[0])
			nurl = strings.TrimSpace(parts[1])
		} else {
			name = fmt.Sprintf("unknown%d", index)
			nurl = strings.TrimSpace(parts[0])
		}

		u, err := parseURL(nurl, "http")
		if err != nil {
			logger.Error(err)
		}

		user := ""
		password := ""
		if u.User != nil {
			user = u.User.Username()
			password, _ = u.User.Password()
			u.User = nil // remove user
		}

		promDiscoveryObject := PromDiscoveryObject{
			Name:     name,
			URL:      u.String(),
			User:     user,
			Password: password,
		}

		promDiscoveryObjects = append(promDiscoveryObjects, promDiscoveryObject)
	}
	return promDiscoveryObjects
}

func RemoveEmptyStrings(items []string) []string {

	r := []string{}

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

func ConvertSyncMapToLabelsMap(m SinkMap) LabelsMap {

	r := make(LabelsMap)
	for k, v := range m {
		s, ok := v.(Labels)
		if ok {
			r[k] = s
		}
	}
	return r
}

func ConvertServicesToSinkMap(m Services) SinkMap {

	r := make(SinkMap)
	for k, v := range m {
		r[k] = v
	}
	return r
}

func ConvertSyncMapToServices(m SinkMap) Services {

	r := make(Services)
	for k, v := range m {
		s, ok := v.(*Service)
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

func ConvertLabelMapToSlice(labelsMap LabelsMap) []interface{} {
	r := make([]interface{}, 0)
	for k, v := range labelsMap {
		v["key"] = k
		r = append(r, v)
	}
	return r
}
