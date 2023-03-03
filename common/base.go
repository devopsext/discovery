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

type BaseAvailabilityQuery struct {
	Query   string            `yaml:"query"`
	Suffix  string            `yaml:"suffix"`
	Weight  interface{}       `yaml:"weight"`
	Labels  map[string]string `yaml:"labels"`
	UseCRD  string            `yaml:"crd"`
	Source  string            `yaml:"source"`
	Timeout string            `yaml:"timeout"`
}

type BaseAvailability struct {
	Queries []*BaseAvailabilityQuery `yaml:"queries"`
	GroupBy []string                 `yaml:"group_by"`
	Labels  map[string]string        `yaml:"labels"`
}

type BaseConfig struct {
	Vars         map[string]string `yaml:"vars"`
	Labels       map[string]string `yaml:"labels"`
	Quality      []*BaseQuality    `yaml:"quality"`
	Metrics      []*BaseMetric     `yaml:"metrics"`
	Availability *BaseAvailability `yaml:"availability"`
}

type Service struct {
	Configs []*BaseConfig
	Labels  map[string]string
}

func (ba *BaseAvailability) matchQuery(r *regexp.Regexp) bool {

	for _, v := range ba.Queries {
		if r.MatchString(v.Query) {
			return true
		}
	}
	return false
}

func (bc *BaseConfig) MetricExists(query string) bool {

	r, err := regexp.Compile(query)
	if err != nil {
		return false
	}

	for _, q := range bc.Quality {
		if r.MatchString(q.Query) {
			return true
		}
	}

	for _, m := range bc.Quality {
		if r.MatchString(m.Query) {
			return true
		}
	}

	if bc.Availability != nil {
		return bc.Availability.matchQuery(r)
	}
	return false
}
