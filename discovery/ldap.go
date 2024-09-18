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
	// there is always at least one target
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
		options.BaseDN = conf["basedn"]
		domain := getDomain(options.BaseDN)
		if cred, ok := credentials[domain]; ok {
			options.User = cred.Username
			options.Password = cred.Password
		}
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

func getDomain(dn string) string {
	res := ""
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		if strings.HasPrefix(part, "DC=") {
			res += strings.Split(part, "=")[1] + "."
		}
	}
	return strings.TrimRight(res, ".")
}

func (ldo *LdapOptions) CustomGetObjects() (map[string]map[string]string, error) {
	// connect
	// TODO: Replace with ldap.DialURL
	conn, err := ldap.DialTLS("tcp", ldo.URL, &tls.Config{InsecureSkipVerify: ldo.Insecure})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	//bind
	err = conn.Bind(ldo.User, ldo.Password)
	if err != nil {
		return nil, err
	}

	fullFilter := fmt.Sprintf("(&%s(objectClass=computer))", ldo.Filter) //filter computers only
	if !ldo.DiscoverDisabled {
		fullFilter = fmt.Sprintf("(&%s(!(userAccountControl:1.2.840.113556.1.4.803:=2))(objectClass=computer))", ldo.Filter) // this monster after useracccontrol is just OID for "bitwise and". it's how disabled objects are filtered out in AD
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

		l := len(data)
		if l == 0 {
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
	credentials := make(Credentials)
	err := json.Unmarshal([]byte(password), &credentials)
	if err != nil {
		return nil, err
	}
	return credentials, nil
}
