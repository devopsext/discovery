package discovery

import (
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
)

type AWSOptions struct {
	toolsVendors.AWSKeys
}

type AWSEC2Options struct {
	Schedule string
	AWSOptions
}

type AWSEC2 struct {
	client        *toolsVendors.AWSEC2
	options       AWSEC2Options
	logger        sreCommon.Logger
	observability *common.Observability
	processors    *common.Processors
}

type AWSEC2SinkObject struct {
	sinkMap common.SinkMap
	EC2     *AWSEC2
}

func (os *AWSEC2SinkObject) Map() common.SinkMap {
	return os.sinkMap
}

func (os *AWSEC2SinkObject) Options() interface{} {
	return os.EC2.options
}

func (o *AWSEC2) Name() string {
	return "AWSEC2"
}

func (o *AWSEC2) Source() string {
	return ""
}

func (o *AWSEC2) makeHostsSinkMap(instances []toolsVendors.AWSEC2Instance) common.SinkMap {

	r := make(common.SinkMap)

	for _, v := range instances {
		common.AppendHostSink(r, v.Host, common.HostSink{
			IP:      v.IP,
			Host:    v.Host,
			Vendor:  v.Vendor,
			OS:      v.OS,
			Cluster: v.Cluster,
			Server:  v.Server,
		})
	}
	return r
}

func (o *AWSEC2) Discover() {
	o.logger.Debug("EC2 discovery started")
	instances, err := o.client.GetAllAWSEC2Instances()
	if err != nil {
		o.logger.Error(err)
		return
	}

	if len(instances) == 0 {
		o.logger.Debug("EC2 has no instances")
		return
	}

	hosts := o.makeHostsSinkMap(instances)
	o.logger.Debug("EC2 found %d instances. Processing...", len(hosts))

	o.processors.Process(o, &AWSEC2SinkObject{
		sinkMap: hosts,
		EC2:     o,
	})
}

func NewAWSEC2(options AWSEC2Options, observability *common.Observability, processors *common.Processors) *AWSEC2 {
	logger := observability.Logs()
	if utils.IsEmpty(options.AccessKey) || utils.IsEmpty(options.SecretKey) {
		logger.Debug("AWS keys not present. Skipped")
		return nil
	}

	client, err := toolsVendors.NewAWSEC2(options.AWSKeys)
	if err != nil {
		logger.Debug("couldn't create EC2 object. Skipped")
		logger.Debug(err)
		return nil
	}

	return &AWSEC2{
		client:        client,
		options:       options,
		logger:        logger,
		observability: observability,
		processors:    processors,
	}
}
