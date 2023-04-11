package common

import "regexp"

type BaseQuality struct {
	Range  string `yaml:"range"`
	Every  string `yaml:"every"`
	Points int    `yaml:"points"`
	Query  string `yaml:"query"`
}

type BaseMetric struct {
	Query    string            `yaml:"query"`
	Name     string            `yaml:"name"`
	UniqueBy []string          `yaml:"unique_by"`
	Labels   map[string]string `yaml:"labels"`
}

type BaseAvailability struct {
	Query    string            `yaml:"query"`
	UniqueBy []string          `yaml:"unique_by"`
	Suffix   string            `yaml:"suffix"`
	Labels   map[string]string `yaml:"labels"`
}

type BaseConfig struct {
	Vars         map[string]string   `yaml:"vars"`
	Labels       map[string]string   `yaml:"labels"`
	Qualities    []*BaseQuality      `yaml:"quality"`
	Metrics      []*BaseMetric       `yaml:"metrics"`
	Availability []*BaseAvailability `yaml:"availability"`
}

type Service struct {
	Configs map[string]*BaseConfig
	Labels  map[string]string
	Vars    map[string]string
}

func (ba *BaseAvailability) matchQuery(r *regexp.Regexp) bool {

	if r.MatchString(ba.Query) {
		return true
	}
	return false
}

func (bc *BaseConfig) MetricExists(query string) bool {

	r, err := regexp.Compile(query)
	if err != nil {
		return false
	}

	for _, q := range bc.Qualities {
		if r.MatchString(q.Query) {
			return true
		}
	}

	for _, m := range bc.Qualities {
		if r.MatchString(m.Query) {
			return true
		}
	}

	for _, m := range bc.Availability {
		if m != nil {
			return m.matchQuery(r)
		}

	}

	return false
}
