package discovery

import (
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type ObserviumOptions struct {
	URL      string
	Schedule string
}

type Observium struct {
	options       ObserviumOptions
	logger        sreCommon.Logger
	observability *common.Observability
}

func (o *Observium) Discover() {

	o.logger.Debug("Observium discovery by URL: %s", o.options.URL)

	/*
		if !utils.IsEmpty(t.options.QueryPeriod) {
			// https://Signal.io/docs/Signal/latest/querying/api/#range-queries
			tm := time.Now().UTC()
			t.prometheusOpts.From = common.ParsePeriodFromNow(t.options.QueryPeriod, tm)
			t.prometheusOpts.To = strconv.Itoa(int(tm.Unix()))
			t.prometheusOpts.Step = t.options.QueryStep
			if utils.IsEmpty(t.prometheusOpts.Step) {
				t.prometheusOpts.Step = "15s"
			}
			t.logger.Debug("%s: TCP discovery range: %s <-> %s", t.name, t.prometheusOpts.From, t.prometheusOpts.To)
		}


		data, err := t.prometheus.CustomGet(t.prometheusOpts)
		if err != nil {
			t.logger.Error(err)
			return
		}

		var res common.PrometheusResponse
		if err := json.Unmarshal(data, &res); err != nil {
			t.logger.Error(err)
			return
		}

		if res.Status != "success" {
			t.logger.Error(res.Status)
			return
		}

		if (res.Data == nil) || (len(res.Data.Result) == 0) {
			t.logger.Error("%s: TCP empty data on response", t.name)
			return
		}

		if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
			t.logger.Error("%s: TCP only vector and matrix are allowed", t.name)
			return
		}

		addresses := t.findAddresses(res.Data.Result)
		if len(addresses) == 0 {
			t.logger.Debug("%s: TCP not found any addresses according query", t.name)
			return
		}
		t.logger.Debug("%s: TCP found %d addresses according query", t.name, len(addresses))
		t.createTelegrafConfigs(addresses)
	*/
}

func NewObservium(options ObserviumOptions, observability *common.Observability) *Observium {

	logger := observability.Logs()

	if utils.IsEmpty(options.URL) {
		logger.Debug("Observium has no URL. Skipped")
		return nil
	}

	return &Observium{
		options:       options,
		logger:        logger,
		observability: observability,
	}
}
