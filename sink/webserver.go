package sink

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/discovery"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
)

type WebServerOptions struct {
	ServerName           string
	Listen               string
	Tls                  bool
	Insecure             bool
	Cert                 string
	Key                  string
	Chain                string
	ConfigMetricsLinux   string
	ConfigMetricsWindows string
	Providers            []string
}

type WebServerProcessor = func(w http.ResponseWriter, r *http.Request) error

type WebServer struct {
	options       WebServerOptions
	logger        sreCommon.Logger
	observability *common.Observability
	objects       *sync.Map
}

func (ws *WebServer) Name() string {
	return "WebServer"
}

func (ws *WebServer) Providers() []string {
	return ws.options.Providers
}

func (ws *WebServer) Process(d common.Discovery, so common.SinkObject) {

	dname := d.Name()
	m := so.Map()
	ws.logger.Debug("WebServer has to process %d objects from %s...", len(m), d.Name())

	for k, v := range m {
		name := fmt.Sprintf("%s/%s", strings.ToLower(dname), k)
		ws.objects.Store(name, v)
	}
}

func (ws *WebServer) getPath(base, url string) string {
	path := strings.TrimLeft(url, "/")
	return strings.Replace(path, base, "", 1)
}

func (ws *WebServer) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s1, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		ws.logger.Error(err)
		return def
	}
	return s1
}

func (ws *WebServer) processPubSub(w http.ResponseWriter, r *http.Request) error {

	base := strings.ToLower("PubSub")
	path := ws.getPath(base, r.URL.Path)
	name := fmt.Sprintf("%s%s", base, path)

	obj, _ := ws.objects.Load(name)
	if utils.IsEmpty(obj) {
		return fmt.Errorf("WebServer couldn't load %s for %s", base, name)
	}

	if utils.IsEmpty(obj) {
		msg := fmt.Sprintf("WebServer couldn't find %s file: %s", base, name)
		return fmt.Errorf(msg)
	}

	file, ok := obj.(*discovery.PubSubMessagePayloadFile)
	if !ok {
		msg := fmt.Sprintf("WebServer %s has wrong file: %s", base, name)
		return fmt.Errorf(msg)
	}

	if _, err := w.Write(file.Data); err != nil {
		msg := fmt.Sprintf("WebServer couldn't write %s file: %s", base, name)
		return fmt.Errorf(msg)
	}
	return nil
}

func (ws *WebServer) processFiles(w http.ResponseWriter, r *http.Request) error {

	base := strings.ToLower("Files")
	path := ws.getPath(base, r.URL.Path)
	name := fmt.Sprintf("%s%s", base, path)

	obj, _ := ws.objects.Load(name)
	if utils.IsEmpty(obj) {
		return fmt.Errorf("WebServer couldn't load %s for %s", base, name)
	}

	fpath, ok := obj.(string)
	if !ok {
		return fmt.Errorf("WebServer %s has wrong path: %s", base, name)
	}

	http.ServeFile(w, r, fpath)
	return nil
}

func (ws *WebServer) processConfig(w http.ResponseWriter, r *http.Request) error {

	var content []byte

	base := strings.ToLower("Files")
	path := ws.getPath("configs", r.URL.Path)

	if ext := strings.LastIndex(path, "."); ext == -1 {
		switch path {
		case "/metrics-linux":
			path = "/" + ws.options.ConfigMetricsLinux
		case "/metrics-windows":
			path = "/" + ws.options.ConfigMetricsWindows
		default:
			return fmt.Errorf("WebServer couldn't find a config file for this path: %s", path)
		}
	}

	name := fmt.Sprintf("%s%s", base, path)

	obj, _ := ws.objects.Load(name)
	if utils.IsEmpty(obj) {
		return fmt.Errorf("WebServer couldn't load %s for %s", base, name)
	}

	fpath, ok := obj.(string)
	if !ok {
		return fmt.Errorf("WebServer %s has wrong path: %s", base, name)
	}

	params := r.URL.Query()

	fileInfo, err := os.Stat(fpath)
	if err != nil {
		return fmt.Errorf("WebServer couldn't get info about the config file %s", fpath)
	} else {
		content, err = os.ReadFile(fpath)
		if err != nil {
			return fmt.Errorf("WebServer couldn't read the config file %s", fpath)
		}
	}

	configOpts := toolsRender.TemplateOptions{
		Content: string(content),
		Name:    "telegraf-config",
	}
	telegrafConfigTemplate, err := toolsRender.NewTextTemplate(configOpts, ws.observability)
	if err != nil {
		return fmt.Errorf("WebServer couldn't template the config file %s, error: %s", fpath, err)
	}
	telegrafConfig := ws.render(telegrafConfigTemplate, "Don't have a template", params)

	modTime := fileInfo.ModTime().UTC()
	w.Header().Set("Last-Modified", modTime.Format(http.TimeFormat))
	if _, err := w.Write([]byte(telegrafConfig)); err != nil {
		msg := fmt.Sprintf("WebServer couldn't write the config file: %s", name)
		return fmt.Errorf(msg)
	}
	return nil
}

func (ws *WebServer) processURL(url string, mux *http.ServeMux, p WebServerProcessor) {

	urls := strings.Split(url, ",")
	for _, url := range urls {

		mux.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {

			err := p(w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				ws.logger.Error(err)
			}
		})
	}
}

func (ws *WebServer) Start(wg *sync.WaitGroup) {

	wg.Add(1)
	go func(wg *sync.WaitGroup) {

		defer wg.Done()
		ws.logger.Info("WebServer start...")

		var caPool *x509.CertPool
		var certificates []tls.Certificate

		if ws.options.Tls {

			// load certififcate
			var cert []byte
			if _, err := os.Stat(ws.options.Cert); err == nil {

				cert, err = os.ReadFile(ws.options.Cert)
				if err != nil {
					ws.logger.Panic(err)
				}
			} else {
				cert = []byte(ws.options.Cert)
			}

			// load key
			var key []byte
			if _, err := os.Stat(ws.options.Key); err == nil {
				key, err = os.ReadFile(ws.options.Key)
				if err != nil {
					ws.logger.Panic(err)
				}
			} else {
				key = []byte(ws.options.Key)
			}

			// make pair from certificate and pair
			pair, err := tls.X509KeyPair(cert, key)
			if err != nil {
				ws.logger.Panic(err)
			}

			certificates = append(certificates, pair)

			// load CA chain
			var chain []byte
			if _, err := os.Stat(ws.options.Chain); err == nil {
				chain, err = os.ReadFile(ws.options.Chain)
				if err != nil {
					ws.logger.Panic(err)
				}
			} else {
				chain = []byte(ws.options.Chain)
			}

			// make pool of chains
			caPool = x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(chain) {
				ws.logger.Debug("WebServer CA chain is invalid")
			}
		}

		mux := http.NewServeMux()

		processors := ws.getProcessors()
		for u, p := range processors {
			ws.processURL(u, mux, p)
		}

		listener, err := net.Listen("tcp", ws.options.Listen)
		if err != nil {
			ws.logger.Panic(err)
		}

		ws.logger.Info("WebServer is up. Listening...")

		srv := &http.Server{
			Handler:  mux,
			ErrorLog: nil,
		}

		if ws.options.Tls {

			srv.TLSConfig = &tls.Config{
				Certificates:       certificates,
				RootCAs:            caPool,
				InsecureSkipVerify: ws.options.Insecure,
				ServerName:         ws.options.ServerName,
			}

			err = srv.ServeTLS(listener, "", "")
			if err != nil {
				ws.logger.Panic(err)
			}
		} else {
			err = srv.Serve(listener)
			if err != nil {
				ws.logger.Panic(err)
			}
		}
	}(wg)
}

func (ws *WebServer) getProcessors() map[string]WebServerProcessor {

	m := make(map[string]WebServerProcessor)
	m["/pubsub/*"] = ws.processPubSub
	m["/files/*"] = ws.processFiles
	m["/configs/*"] = ws.processConfig
	return m
}

func NewWebServer(options WebServerOptions, observability *common.Observability) *WebServer {

	logger := observability.Logs()

	if utils.IsEmpty(options.Listen) {
		logger.Debug("WebServer sink is not enabled. Skipped")
		return nil
	}

	options.Providers = common.RemoveEmptyStrings(options.Providers)

	return &WebServer{
		options:       options,
		logger:        logger,
		observability: observability,
		objects:       &sync.Map{},
	}
}
