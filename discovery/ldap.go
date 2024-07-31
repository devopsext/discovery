package discovery

import (
	"crypto/tls"
	"strconv"
	"strings"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"github.com/go-ldap/ldap"
)

type LdapGlobalOptions struct {
	ConfigString string
	Timeout      int
	Insecure     bool
	Schedule     string
}

type LdapOptions struct {
	Timeout    int
	Insecure   bool
	URL        string
	User       string
	Password   string
	Token      string
	BaseDN     string
	Domain     string
	Scope      int //ScopeBaseObject   = 0 ScopeSingleLevel  = 1 ScopeWholeSubtree = 2
	Filter     string
	Attributes []string
	Schedule   string
	Cert       string
}

type Ldap struct {
	//client        *toolsVendors.Ldap
	options       LdapOptions
	logger        sreCommon.Logger
	observability *common.Observability
	processors    *common.Processors
}

type LdapSinkObject struct {
	sinkMap common.SinkMap
	ldap    *Ldap
}

func (ls *LdapSinkObject) Map() common.SinkMap {
	return ls.sinkMap
}

func (ls *LdapSinkObject) Options() interface{} {
	return ls.ldap.options
}

func (ld *Ldap) Name() string {
	return "Ldap"
}

func (ld *Ldap) Source() string {
	return ld.options.Domain
}

func GetLdapDiscoveryTargets(GlobalOptions LdapGlobalOptions, logger sreCommon.Logger) ([]LdapOptions, error) {
	//TODO parse config string into array of ldapoptions
	//user=asdfasdf|pass=asdfasdf|source=asdfsd|country=c|vendor=provider|attributes=asdfasdf!asdasdf!asdfasdf;user=zxcvzxcv|pass=zxcvzxcv|source=zxcvzxv|country=c1|vendor=ven
	var optionsArray []LdapOptions
	for _, target := range strings.Split(strings.TrimSpace(GlobalOptions.ConfigString), ";") {
		var options LdapOptions
		m := make(map[string]string)
		for _, param := range strings.Split(strings.TrimSpace(target), "|") {
			name, value, found := strings.Cut(strings.TrimSpace(param), "=")
			if found {
				m[name] = value
			}
		}
		options.URL = m["url"]
		options.Timeout = GlobalOptions.Timeout
		options.Insecure = GlobalOptions.Insecure
		options.User = m["user"]
		options.Password = m["password"]
		options.BaseDN = m["basedn"]
		options.Domain = m["domain"]
		options.Scope, _ = strconv.Atoi(m["scope"]) //ScopeBaseObject   = 0 ScopeSingleLevel  = 1 ScopeWholeSubtree = 2
		options.Filter = m["filter"]
		options.Attributes = strings.Split(m["attributes"], "!")
		if schedule, ok := m["schedule"]; ok { // to be able to override schedule for some targets
			options.Schedule = schedule
		} else {
			options.Schedule = GlobalOptions.Schedule
		}
		optionsArray = append(optionsArray, options)
	}
	return optionsArray, nil //TODO catch possible errors and bail out
}

func (ld *Ldap) CustomGetObjects(options LdapOptions) (map[string]map[string]string, error) {
	// connect
	conn, err := ldap.DialTLS("tcp", options.URL, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	//bind
	err = conn.Bind(options.User, options.Password)
	if err != nil {
		return nil, err
	}

	query := &ldap.SearchRequest{
		BaseDN:     options.BaseDN,
		Scope:      options.Scope,
		Filter:     options.Filter,
		Attributes: options.Attributes,
	}

	searchResults, err := conn.Search(query)
	if err != nil {
		return nil, err
	}

	objects := make(map[string]map[string]string)
	for _, object := range searchResults.Entries {
		attrs := make(map[string]string)
		for _, attr := range object.Attributes {
			attrs[attr.Name] = strings.Join(attr.Values, ",")
		}
		objects[object.DN] = attrs
	}
	return objects, nil
}

func (ld *Ldap) GetObjects() (map[string]map[string]string, error) {
	return ld.CustomGetObjects(ld.options)
}

func (ld *Ldap) makeObjectSinkMap(mtsat map[string]map[string]string) common.SinkMap {

	r := make(common.SinkMap)

	for k, v := range mtsat {

		r[k] = common.MergeLabels(common.Labels{
			"ParentObject": v["location"], //don't ask why
			"Vendor":       v["Provider"],
			"os":           v["operatingSystem"],
			"country":      v["c"],
			"location":     v["l"],
		})
	}
	return r
}

func (ld *Ldap) Discover() {

	ld.logger.Debug("Ldap discovery in domain %s by URL: %s", ld.options.Domain, ld.options.URL)

	data, err := ld.CustomGetObjects(ld.options)
	if err != nil {
		ld.logger.Error(err)
		return
	}

	l := len(data)
	if l == 0 {
		ld.logger.Debug("Ldap %s has no objects according to BaseDN, filter and scope.", ld.options.URL)
	}

	objects := ld.makeObjectSinkMap(data)
	ld.logger.Debug("Ldap %s found %d objects. Processing...", ld.options.URL, len(objects))

	ld.processors.Process(ld, &LdapSinkObject{
		sinkMap: objects,
		ldap:    ld,
	})
}

func NewLdap(options LdapOptions, observability *common.Observability, processors *common.Processors) *Ldap {

	logger := observability.Logs()

	if utils.IsEmpty(options.URL) {
		logger.Debug("Ldap has no URL. Skipped")
		return nil
	}

	return &Ldap{
		options:       options,
		logger:        logger,
		observability: observability,
		processors:    processors,
	}
}
