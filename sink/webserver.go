package sink

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/allegro/bigcache"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/discovery"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
)

type WebServerOptions struct {
	ServerName string
	Listen     string
	Tls        bool
	Insecure   bool
	Cert       string
	Key        string
	Chain      string
	Providers  []string
	RenderTTL  time.Duration // render cache ttl in minutes
}

type WebServerProcessor = func(w http.ResponseWriter, r *http.Request) error

type WebServer struct {
	options       WebServerOptions
	logger        sreCommon.Logger
	observability *common.Observability
	objects       *sync.Map
	renderCache   *bigcache.BigCache
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

func (ws *WebServer) getPath(base, url string) (string, error) {
	upath := strings.TrimLeft(url, "/")
	upath = strings.Replace(upath, base, "", 1)
	upath = path.Clean(upath)

	// Ensure the path is NOT within the base directory
	if strings.HasPrefix(upath, base) {
		return "", fmt.Errorf("invalid path: %s", upath)
	}

	return upath, nil
}

func (ws *WebServer) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {
	if res, err := common.RenderTemplate(tpl, def, obj); err != nil {
		ws.logger.Error(err)
		return def
	} else {
		return res
	}
}

func (ws *WebServer) processPubSub(w http.ResponseWriter, r *http.Request) error {
	base := "pubsub"
	upath, err := ws.getPath(base, r.URL.Path)
	if err != nil {
		return err
	}
	name := path.Join(base, upath)

	obj, _ := ws.objects.Load(name)
	if utils.IsEmpty(obj) {
		return fmt.Errorf("WebServer couldn't load %s for %s", base, name)
	}

	file, ok := obj.(*discovery.PubSubMessagePayloadFile)
	if !ok {
		return fmt.Errorf("WebServer %s has wrong file: %s", base, name)
	}

	if _, err := w.Write(file.Data); err != nil {
		return fmt.Errorf("WebServer couldn't write %s file: %s", base, name)
	}
	return nil
}

func (ws *WebServer) processFiles(w http.ResponseWriter, r *http.Request) error {
	base := "files"
	upath, err := ws.getPath(base, r.URL.Path)
	if err != nil {
		return err
	}
	name := path.Join(base, upath)

	obj, _ := ws.objects.Load(name)
	if utils.IsEmpty(obj) {
		return fmt.Errorf("WebServer couldn't load %s for %s", base, name)
	}

	fpath, ok := obj.(string)
	if !ok {
		return fmt.Errorf("WebServer %s has wrong path: %s", base, name)
	}
	switch r.Method {
	case http.MethodGet:
		http.ServeFile(w, r, fpath)
	case http.MethodHead:
		fileInfo, err := os.Stat(fpath)
		if err != nil {
			return fmt.Errorf("WebServer couldn't get info about the file %s", fpath)
		}
		modTime := fileInfo.ModTime().UTC()
		w.Header().Set("Last-Modified", modTime.Format(http.TimeFormat))
	}
	return nil
}

func (ws *WebServer) processConfig(w http.ResponseWriter, r *http.Request) error {
	base := "files"
	upath, err := ws.getPath("configs", r.URL.Path)
	if err != nil {
		return err
	}
	upath = strings.TrimLeft(upath, "/")

	// if path is not a file - return the default config
	if ext := strings.LastIndex(upath, "."); ext == -1 {
		upath = path.Join(upath, "default.conf.tmpl")
	}

	// convert path like /metrics/windows/telegraf.conf -> /metrics_windows_telegraf.conf
	upath = strings.ReplaceAll(upath, "/", "_")
	name := path.Join(base, upath)

	obj, ok := ws.objects.Load(name)
	if !ok || utils.IsEmpty(obj) {
		return fmt.Errorf("WebServer couldn't load %s for %s", base, name)
	}

	fpath, ok := obj.(string)
	if !ok {
		return fmt.Errorf("WebServer %s has wrong path: %s", base, name)
	}

	fileInfo, err := os.Stat(fpath)
	if err != nil {
		return fmt.Errorf("WebServer couldn't get info about the config file %s", fpath)
	}
	modTime := fileInfo.ModTime().UTC()
	w.Header().Set("Last-Modified", modTime.Format(http.TimeFormat))

	switch r.Method {
	case http.MethodGet:

		key := r.URL.String()
		var telegrafConfig []byte
		if telegrafConfig, err = ws.renderCache.Get(key); err != nil {
			ws.logger.Debug("WebServer cache miss for: %s", key)
			content, err := os.ReadFile(fpath)
			if err != nil {
				return fmt.Errorf("WebServer couldn't read the config file %s", fpath)
			}

			params := r.URL.Query()
			configOpts := toolsRender.TemplateOptions{
				Content: string(content),
				Name:    "telegraf-config",
			}
			telegrafConfigTemplate, err := toolsRender.NewTextTemplate(configOpts, ws.observability)
			if err != nil {
				return fmt.Errorf("WebServer couldn't template the config file %s, error: %s", fpath, err)
			}
			telegrafConfig = []byte(ws.render(telegrafConfigTemplate, "Don't have a template", params))
			if err = ws.renderCache.Set(key, telegrafConfig); err != nil {
				ws.logger.Warn("WebServer couldn't cache render: %s", key)
			}
		}

		if _, err := w.Write(telegrafConfig); err != nil {
			return fmt.Errorf("WebServer couldn't write the config file: %s", name)
		}
	case http.MethodHead:
		w.Header().Set("Content-Length", "0")
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}

	return nil
}

func (ws *WebServer) processURL(url string, mux *http.ServeMux, p WebServerProcessor) {
	urls := strings.Split(url, ",")
	for _, url := range urls {
		mux.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
			if err := p(w, r); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				ws.logger.Error(err)
			}
		})
	}
}

func (ws *WebServer) Start(wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ws.logger.Info("WebServer start...")

		var caPool *x509.CertPool
		var certificates []tls.Certificate

		if ws.options.Tls {
			cert, err := loadFileOrString(ws.options.Cert)
			if err != nil {
				ws.logger.Panic(err)
			}

			key, err := loadFileOrString(ws.options.Key)
			if err != nil {
				ws.logger.Panic(err)
			}

			pair, err := tls.X509KeyPair(cert, key)
			if err != nil {
				ws.logger.Panic(err)
			}
			certificates = append(certificates, pair)

			chain, err := loadFileOrString(ws.options.Chain)
			if err != nil {
				ws.logger.Panic(err)
			}

			caPool = x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(chain) {
				ws.logger.Debug("WebServer CA chain is invalid")
			}
		}

		mux := http.NewServeMux()
		for u, p := range ws.getProcessors() {
			ws.processURL(u, mux, p)
		}

		listener, err := net.Listen("tcp", ws.options.Listen)
		if err != nil {
			ws.logger.Panic(err)
		}

		ws.logger.Info("WebServer is up. Listening...")

		srv := &http.Server{
			Handler: mux,
		}

		if ws.options.Tls {
			srv.TLSConfig = &tls.Config{
				Certificates:       certificates,
				RootCAs:            caPool,
				InsecureSkipVerify: ws.options.Insecure,
				ServerName:         ws.options.ServerName,
			}
			err = srv.ServeTLS(listener, "", "")
		} else {
			err = srv.Serve(listener)
		}
		if err != nil {
			ws.logger.Panic(err)
		}
	}()
}

func (ws *WebServer) getProcessors() map[string]WebServerProcessor {
	return map[string]WebServerProcessor{
		"/pubsub/":  ws.processPubSub,
		"/files/":   ws.processFiles,
		"/configs/": ws.processConfig,
	}
}

func NewWebServer(options WebServerOptions, observability *common.Observability) *WebServer {
	logger := observability.Logs()

	if utils.IsEmpty(options.Listen) {
		logger.Debug("WebServer sink is not enabled. Skipped")
		return nil
	}

	options.Providers = common.RemoveEmptyStrings(options.Providers)

	cacheConfig := bigcache.DefaultConfig(options.RenderTTL)
	// clean up expired items in every 1 minute
	cacheConfig.CleanWindow = 1 * time.Minute
	// set the maximum number of entries in the cache
	cacheConfig.MaxEntriesInWindow = 1500
	// set the maximum size of the entry in bytes
	cacheConfig.MaxEntrySize = 4096

	renderCache, err := bigcache.NewBigCache(cacheConfig)
	if err != nil {
		logger.Error(err)
		return nil
	}

	return &WebServer{
		options:       options,
		logger:        logger,
		observability: observability,
		objects:       &sync.Map{},
		renderCache:   renderCache,
	}
}

func loadFileOrString(pathOrContent string) ([]byte, error) {
	if _, err := os.Stat(pathOrContent); err == nil {
		return os.ReadFile(pathOrContent)
	}
	return []byte(pathOrContent), nil
}
