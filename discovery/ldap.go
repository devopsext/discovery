package discovery

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"github.com/go-ldap/ldap/v3"
)

type LdapGlobalOptions struct {
	ConfigString string
	Password     string
	Timeout      int
	Insecure     bool
	Schedule     string
}

type LdapOptions struct {
	Timeout          int
	Insecure         bool
	URL              string
	User             string
	Password         string
	BaseDN           string
	Kind             string
	Scope            int //ScopeBaseObject   = 0 ScopeSingleLevel  = 1 ScopeWholeSubtree = 2
	Filter           string
	Attributes       []string
	Fields           map[string]string
	Schedule         string
	Cert             string
	DiscoverDisabled bool
}

type Ldap struct {
	targets       []LdapOptions
	logger        sreCommon.Logger
	observability *common.Observability
	processors    *common.Processors
}

type LdapSinkObject struct {
	sinkMap common.SinkMap
	ldap    *Ldap
}

type Credential struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type Credentials map[string]Credential

func (ls *LdapSinkObject) Map() common.SinkMap {
	return ls.sinkMap
}

func (ls *LdapSinkObject) Options() interface{} {
	// there is always at least one target
	return ls.ldap.targets[0]
}

func (ld *Ldap) Name() string {
	return "Ldap"
}

func (ld *Ldap) Source() string {
	return ld.targets[0].URL
}

func (ldo *LdapOptions) PrepareLabels(data map[string]string) common.Labels {

	labels := make(common.Labels)
	for k, v := range ldo.Fields {
		if !utils.IsEmpty(v) { // skip fields for which no mapping is set in config
			labels[k] = data[v]
		}
	}
	labels["kind"] = ldo.Kind
	return labels
}

func GetLdapDiscoveryTargets(GlobalOptions LdapGlobalOptions, credentials Credentials, logger sreCommon.Logger) ([]LdapOptions, error) {
	var optionsArray []LdapOptions
	for _, target := range strings.Split(strings.TrimSpace(GlobalOptions.ConfigString), ";") {
		var options LdapOptions

		conf := make(map[string]string)
		fieldconf := make(map[string]string)
		for _, param := range strings.Split(strings.TrimSpace(target), "|") {
			name, value, found := strings.Cut(strings.TrimSpace(param), "=")
			if found {
				if strings.HasPrefix(name, "f:") {
					fieldconf[name[2:]] = strings.ToLower(value)
				} else {
					conf[name] = value
				}
			}
		}
		options.URL = conf["url"]
		options.Timeout = GlobalOptions.Timeout
		options.BaseDN = conf["basedn"]
		domain := getDomain(options.BaseDN)
		if cred, ok := credentials[domain]; ok {
			options.User = cred.Username
			options.Password = cred.Password
		}
		options.Kind = conf["kind"]
		options.Scope, _ = strconv.Atoi(conf["scope"])
		options.Filter = conf["filter"]
		options.Fields = fieldconf
		options.Attributes = append([]string{"name"}, fieldconfToSlice(fieldconf)...)
		options.DiscoverDisabled = parseBoolOrDefault(conf["discoverdisabled"], false)
		options.Schedule = confOrDefault(conf["schedule"], GlobalOptions.Schedule)
		options.Insecure = parseBoolOrDefault(conf["insecure"], GlobalOptions.Insecure)
		optionsArray = append(optionsArray, options)
	}
	return optionsArray, nil
}

func getDomain(dn string) string {
	var res strings.Builder
	for _, part := range strings.Split(dn, ",") {
		if strings.HasPrefix(part, "DC=") {
			res.WriteString(strings.Split(part, "=")[1] + ".")
		}
	}
	return strings.TrimRight(res.String(), ".")
}

func (ldo *LdapOptions) CustomGetObjects() (map[string]map[string]string, error) {
	// TODO: Replace with ldap.DialURL
	conn, err := ldap.DialTLS("tcp", ldo.URL, &tls.Config{InsecureSkipVerify: ldo.Insecure})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.Bind(ldo.User, ldo.Password); err != nil {
		return nil, err
	}

	fullFilter := fmt.Sprintf("(&%s(objectClass=computer))", ldo.Filter)
	if !ldo.DiscoverDisabled {
		fullFilter = fmt.Sprintf("(&%s(!(userAccountControl:1.2.840.113556.1.4.803:=2))(objectClass=computer))", ldo.Filter)
	}
	query := &ldap.SearchRequest{
		BaseDN:     ldo.BaseDN,
		Scope:      ldo.Scope,
		Filter:     fullFilter,
		Attributes: ldo.Attributes,
	}

	searchResults, err := conn.Search(query)
	if err != nil {
		return nil, err
	}

	objects := make(map[string]map[string]string)
	for _, object := range searchResults.Entries {
		attrs := make(map[string]string)
		for _, attr := range object.Attributes {
			attrs[strings.ToLower(attr.Name)] = strings.Join(attr.Values, ",")
		}
		objects[object.GetAttributeValue("name")] = attrs
	}
	return objects, nil
}

func (ldo *LdapOptions) GetObjects() (map[string]map[string]string, error) {
	return ldo.CustomGetObjects()
}

func (ldo *LdapOptions) makeObjectSinkMap(objects map[string]map[string]string) common.SinkMap {
	r := make(common.SinkMap)
	for k, v := range objects {
		r[k] = ldo.PrepareLabels(v)
	}
	return r
}

func (ld *Ldap) Discover() {
	res := make(common.SinkMap)
	for _, target := range ld.targets {
		if utils.IsEmpty(target.URL) {
			ld.logger.Warn("Ldap target has no URL. Skipped")
			continue
		}

		ld.logger.Debug("Ldap discovery of kind %s by URL: %s", target.Kind, target.URL)
		data, err := target.CustomGetObjects()
		if err != nil {
			ld.logger.Error(err)
			continue
		}

		if len(data) == 0 {
			ld.logger.Warn("Ldap %s@%s has no objects according to BaseDN, filter and scope.", target.Kind, target.URL)
			continue
		}

		objects := target.makeObjectSinkMap(data)
		ld.logger.Debug("Ldap %s found %d objects. Processing...", target.URL, len(objects))
		for k, v := range objects {
			res[k] = v
		}
	}

	ld.processors.Process(ld, &LdapSinkObject{
		sinkMap: res,
		ldap:    ld,
	})
}

func NewLdap(options LdapGlobalOptions, observability *common.Observability, processors *common.Processors) *Ldap {
	logger := observability.Logs()
	credentials, err := extractCredentials(options.Password)
	if err != nil {
		logger.Warn("Cannot extract credentials from password: %s", err)
	}

	targets, err := GetLdapDiscoveryTargets(options, credentials, logger)
	if err != nil {
		logger.Error(err)
		return nil
	}

	if len(targets) == 0 {
		logger.Warn("No Ldap targets found")
		return nil
	}

	return &Ldap{
		targets:       targets,
		logger:        logger,
		observability: observability,
		processors:    processors,
	}
}

func extractCredentials(password string) (Credentials, error) {
	var credentials Credentials
	err := json.Unmarshal([]byte(password), &credentials)
	return credentials, err
}

func fieldconfToSlice(fieldconf map[string]string) []string {
	var fields []string
	for _, v := range fieldconf {
		fields = append(fields, v)
	}
	return fields
}

func parseBoolOrDefault(value string, defaultValue bool) bool {
	if parsedValue, err := strconv.ParseBool(value); err == nil {
		return parsedValue
	}
	return defaultValue
}

func confOrDefault(value, defaultValue string) string {
	if value != "" {
		return value
	}
	return defaultValue
}
