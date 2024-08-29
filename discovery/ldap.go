package discovery

import (
	"crypto/tls"
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
	Password     string // get separately
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
	return ld.options.URL
}

func (ld *Ldap) PrepareLabels(data map[string]string) common.Labels {

	labels := make(common.Labels)
	for k, v := range ld.options.Fields {
		if !utils.IsEmpty(v) { // skip fields for which no mapping is set in config
			labels[k] = data[v]
		}
	}
	labels["kind"] = ld.options.Kind
	return labels
}

func GetLdapDiscoveryTargets(GlobalOptions LdapGlobalOptions, logger sreCommon.Logger) ([]LdapOptions, error) {
	//config is something like:
	//"url=localhost:8889|kind=DC|user=CN=user,DC=domain,DC=com|password=***|basedn=OU=servers,DC=domain,DC=com|scope=2|filter=(location=*)|f:parent=realdns|f:country=c|f:city=l|f:vendor=Provider|f:os=OperatingSystem|f:host=dnshostname;<second config>;<third config>...",

	var optionsArray []LdapOptions
	for _, target := range strings.Split(strings.TrimSpace(GlobalOptions.ConfigString), ";") {
		var options LdapOptions

		conf := make(map[string]string)
		fieldconf := make(map[string]string)
		for _, param := range strings.Split(strings.TrimSpace(target), "|") {
			name, value, found := strings.Cut(strings.TrimSpace(param), "=")
			if found {
				if (len(name) > 2) && (name[:2] == "f:") { //if name of conf parameter starts with 'f:' - it's field config (checking that at least 1 symbol will be left after removing 'f:' from name)
					fieldconf[name[2:]] = value
				} else { // just a regular config
					conf[name] = value
				}
			}
		}
		// common config
		options.URL = conf["url"]
		options.Timeout = GlobalOptions.Timeout
		options.User = conf["user"]
		options.Password = GlobalOptions.Password
		options.BaseDN = conf["basedn"]
		options.Kind = conf["kind"]
		options.Scope, _ = strconv.Atoi(conf["scope"]) //ScopeBaseObject   = 0 ScopeSingleLevel  = 1 ScopeWholeSubtree = 2
		options.Filter = conf["filter"]

		// fields and attributes
		options.Fields = make(map[string]string)
		for k, v := range fieldconf {
			options.Fields[k] = strings.ToLower(v)
		}

		options.Attributes = []string{"name"} //we always need name
		for _, v := range options.Fields {    // and all the fields we are using to extract data
			options.Attributes = append(options.Attributes, v)
		}

		// overriding globals if respective config present
		if _, ok := conf["discoverdisabled"]; ok { // drop disabled objects (default) or keep them in the output
			if discoverDisabled, ok := strconv.ParseBool(conf["discoverdisabled"]); ok != nil {
				options.DiscoverDisabled = discoverDisabled
			}
		} else {
			options.DiscoverDisabled = false
		}

		if schedule, ok := conf["schedule"]; ok { // to be able to override schedule for some targets
			options.Schedule = schedule
		} else {
			options.Schedule = GlobalOptions.Schedule
		}

		if _, ok := conf["insecure"]; ok { // to be able to override insecure for some targets
			if insecure, ok := strconv.ParseBool(conf["insecure"]); ok != nil {
				options.Insecure = insecure
			}
		} else {
			options.Insecure = GlobalOptions.Insecure
		}

		optionsArray = append(optionsArray, options)
	}
	return optionsArray, nil //TODO catch possible errors and bail out
}

func (ld *Ldap) CustomGetObjects() (map[string]map[string]string, error) {
	// connect
	// TODO: Replace with ldap.DialURL
	conn, err := ldap.DialTLS("tcp", ld.options.URL, &tls.Config{InsecureSkipVerify: ld.options.Insecure})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	//bind
	err = conn.Bind(ld.options.User, ld.options.Password)
	if err != nil {
		return nil, err
	}

	fullFilter := fmt.Sprintf("(&%s(objectClass=computer))", ld.options.Filter) //filter computers only
	if !ld.options.DiscoverDisabled {
		fullFilter = fmt.Sprintf("(&%s(!(userAccountControl:1.2.840.113556.1.4.803:=2))(objectClass=computer))", ld.options.Filter) // this monster after useracccontrol is just OID for "bitwise and". it's how disabled objects are filtered out in AD
	}
	query := &ldap.SearchRequest{
		BaseDN:     ld.options.BaseDN,
		Scope:      ld.options.Scope,
		Filter:     fullFilter,
		Attributes: ld.options.Attributes,
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

func (ld *Ldap) GetObjects() (map[string]map[string]string, error) {
	return ld.CustomGetObjects()
}

func (ld *Ldap) makeObjectSinkMap(objects map[string]map[string]string) common.SinkMap {

	r := make(common.SinkMap)

	for k, v := range objects {

		r[k] = ld.PrepareLabels(v)

	}
	return r
}

func (ld *Ldap) Discover() {

	ld.logger.Debug("Ldap discovery of kind %s by URL: %s", ld.options.Kind, ld.options.URL)

	data, err := ld.CustomGetObjects()
	if err != nil {
		ld.logger.Error(err)
		return
	}

	l := len(data)
	if l == 0 {
		ld.logger.Debug("Ldap %s@%s has no objects according to BaseDN, filter and scope.", ld.options.Kind, ld.options.URL)
		return
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
