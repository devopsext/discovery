package discovery

import (
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
)

type LdapOptions struct {
	toolsVendors.LdapOptions
	Schedule string
}

type Ldap struct {
	client        *toolsVendors.Ldap
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

	data, err := ld.client.CustomGetObjects(ld.options.LdapOptions)
	if err != nil {
		ld.logger.Error(err)
		return
	}

	l := len(data)
	if l == 0 {
		ld.logger.Debug("Ldap has no objects according to BaseDN, filter and scope.")
	}

	objects := ld.makeObjectSinkMap(data)
	ld.logger.Debug("Ldap found %d objects. Processing...", len(objects))

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
		client:        toolsVendors.NewLdap(options.LdapOptions),
		options:       options,
		logger:        logger,
		observability: observability,
		processors:    processors,
	}
}
