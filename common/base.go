package common

import (
	"regexp"
	"strings"

	"github.com/devopsext/utils"
)

type BaseQuality struct {
	Range  string `yaml:"range"`
	Every  string `yaml:"every"`
	Points int    `yaml:"points"`
	Query  string `yaml:"query"`
}

type BaseMetric struct {
	Disabled bool              `yaml:"disabled"`
	Query    string            `yaml:"query"`
	Name     string            `yaml:"name"`
	UniqueBy []string          `yaml:"unique_by"`
	Labels   map[string]string `yaml:"labels"`
}

type BaseAvailability struct {
	Disabled bool                     `yaml:"disabled"`
	Queries  []*BaseAvailabilityQuery `yaml:"queries"`
	GroupBy  []string                 `yaml:"group_by"`
	Labels   map[string]string        `yaml:"labels"`
}

type BaseAvailabilityQuery struct {
	Query     string            `yaml:"query"`
	Suffix    string            `yaml:"suffix"`
	Weight    interface{}       `yaml:"weight"`
	Labels    map[string]string `yaml:"labels"`
	UseCRD    string            `yaml:"crd"`
	Composite string            `yaml:"composite"`
	Source    string            `yaml:"source"`
	Timeout   string            `yaml:"timeout"`
}

type BaseCondition struct {
	Metric string            `yaml:"metric"`
	Labels map[string]string `yaml:"labels"`
}

type BaseConfig struct {
	Disabled     bool              `yaml:"disabled"`
	Prefix       string `yaml:"prefix"`
	Vars         map[string]string `yaml:"vars"`
	Labels       map[string]string `yaml:"labels"`
	Conditions   []*BaseCondition  `yaml:"if"`
	Qualities    []*BaseQuality    `yaml:"quality"`
	Metrics      []*BaseMetric     `yaml:"metrics"`
	Availability *BaseAvailability `yaml:"availability"`
}

type File struct {
	Path string
	Type string
	Obj  interface{}
}

type Service struct {
	Metrics []string
	Configs map[string]*BaseConfig
	Labels  map[string]string
	Vars    map[string]string
	Files   map[string]*File
}

type Labels map[string]string

func (bc *BaseConfig) LabelsExist(c *BaseCondition, labels map[string]string) bool {

	if labels == nil {
		return true
	}

	keys := GetStringKeys(labels)
	for k, v := range c.Labels {
		if !utils.Contains(keys, k) {
			return false
		}
		r, err := regexp.Compile(v)
		if err != nil {
			continue
		}
		if !(r.MatchString(labels[k]) || labels[k] == v) {
			return false
		}
	}
	return true
}

func (bc *BaseConfig) Contains(pattern string) bool {

	for _, q := range bc.Qualities {
		if strings.Contains(q.Query, pattern) {
			return true
		}
	}

	for _, m := range bc.Qualities {
		if strings.Contains(m.Query, pattern) {
			return true
		}
	}

	if bc.Availability != nil {
		for _, a := range bc.Availability.Queries {
			if strings.Contains(a.Query, pattern) {
				return true
			}
		}
	}
	return false
}

func (bc *BaseConfig) MetricExists(query string, labels map[string]string) bool {

	if len(bc.Conditions) > 0 {

		for _, v := range bc.Conditions {

			r, err := regexp.Compile(v.Metric)
			if err != nil {
				continue
			}
			if r.MatchString(query) && bc.LabelsExist(v, labels) {
				return true
			}
		}
		return false
	}
	return bc.Contains(query)
}
