package main

import (
	"os"
	"errors"
	"flag"
	"fmt"
	"log"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/nu7hatch/gouuid"
	"html/template"
	"net"
	"net/http"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"path"
	"io/ioutil"
	"encoding/base64"
)

type globalConfig struct {
	templatePath string
	templates    map[string]*template.Template
	tmplLock     sync.RWMutex
	httpApiKey   string
	dnsAPIServers []string
}

var config = &globalConfig{
	templates:    make(map[string]*template.Template),
}

// SQL defaults.
var (
	sqlHostname = "localhost"
	sqlPort     = 3306
	sqlUsername = "sdns"
	sqlPassword = ""
	sqlDBName   = "sdns"
)

var decoder = schema.NewDecoder()

func (gc *globalConfig) getTemplate(templates ...string) (*template.Template, error) {
	var (
		err error
		ret *template.Template
	)
	first := templates[0]
	gc.tmplLock.Lock()
	defer gc.tmplLock.Unlock()
	ret, ok := gc.templates[first]
	if ok == false {
		for pos, val := range templates {
			templates[pos] = gc.templatePath + "/templates/" + val
		}
		ret, err = template.ParseFiles(templates...)
		if err == nil {
			gc.templates[first] = ret
		}
	}
	return ret, err
}

func generateUpdateKey() (string, error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return strings.Replace(u.String(), "-", "", -1)[:10], nil
}

func registerDomain(domain, dstIP, accessKey, submitAddress string) (error, error) {
	var (
		err, warning error
	)
	err = dbRegisterDomain(domain, dstIP, accessKey, submitAddress)
	if err != nil {
		return err, warning
	}
	err = dnsRegisterDomain(domain, dstIP)
	if err != nil {
		fmt.Println("Problem talking to dns backend:", err)
		err = nil
		warning = errors.New("Registration reached databases but failed to update dns servers, the update will take a while to propagate.")
	}
	return err, warning
}

func updateDomain(domain, dstIP, accessKey, submitAddress string) (error, error) {
	var (
		err, warning error
	)
	updated, err := dbUpdateDomain(domain, dstIP, accessKey, submitAddress)
	if err != nil {
		return err, warning
	}
	// Only update the dns servers if the sql server was updated.
	if updated {
		err = dnsUpdateDomain(domain, dstIP)
		if err != nil {
			fmt.Println("Problem talking to dns backend:", err)
			err = nil
			warning = errors.New("Registration reached databases but failed to update dns servers, the update will take a while to propagate.")
		}
	}
	return err, warning
}

func isValidDomainName(domain string) bool {
	var valid bool = true
	if len(domain) < 3 {
		valid = false
	} else if strings.ContainsAny(domain, "/") {
		valid = false
	}

	return valid
}

func logHTTPRequest(r *http.Request) {
	addr := getSubmitIP(r)
	if len(addr) == 0 {
		addr = r.RemoteAddr
	}
	log.Printf("%s request from=%s url=%s", r.Method, addr, r.URL)
}

func pIndex(w http.ResponseWriter, r *http.Request) {
	var (
		err, warning    error
		domain string
	)
	type tmplData struct {
		Register   bool
		RegOK      bool
		Domain     string
		Parent     string
		Address    string
		SubmitIP   string
		FullDomain string
		UpdateKey  string
		ErrorMsg   string
	}
	type formData struct {
		Domain  string
		Parent  string
		Address string
	}
	logHTTPRequest(r)
	submitIP := getSubmitIP(r)
	tdata := tmplData{Register: false, RegOK: false, Parent: "dns.routemeister.net", SubmitIP: submitIP}
	fdata := formData{}
	tmpl, err := config.getTemplate("index.html", "base.html")
	if err != nil {
		fmt.Println("ERROR loading template:", err)
		return
	}
	if r.Method == "POST" {
		tdata.Register = true
		err = r.ParseForm()
		if err != nil {
			tdata.ErrorMsg = err.Error()
			tmpl.ExecuteTemplate(w, "base.html", tdata)
			return
		}
		tdata.UpdateKey, err = generateUpdateKey()
		if err != nil {
			tdata.ErrorMsg = err.Error()
			tmpl.ExecuteTemplate(w, "base.html", tdata)
			return
		}
		err := decoder.Decode(&fdata, r.PostForm)
		if err != nil {
			tdata.ErrorMsg = err.Error()
			tmpl.ExecuteTemplate(w, "base.html", tdata)
			return
		}
		if fdata.Address == "" {
			fdata.Address = submitIP
		}
		tdata.Domain = fdata.Domain
		tdata.Parent = fdata.Parent
		tdata.Address = fdata.Address
		if fdata.Parent != "" {
			domain = fdata.Domain + "." + fdata.Parent + "."
			tdata.FullDomain = fdata.Domain + "." + fdata.Parent
		} else {
			domain = fdata.Domain + "."
			tdata.FullDomain = fdata.Domain
		}
		if !isValidDomainName(domain) {
			tdata.ErrorMsg = "Invalid domain name"
			tmpl.ExecuteTemplate(w, "base.html", tdata)
			return
		}
		if net.ParseIP(fdata.Address) == nil {
			tdata.ErrorMsg = "Invalid IP-address"
			tmpl.ExecuteTemplate(w, "base.html", tdata)
			return
		}
		err, warning = registerDomain(domain, fdata.Address, tdata.UpdateKey, submitIP)
		if err != nil {
			tdata.ErrorMsg = err.Error()
			tmpl.ExecuteTemplate(w, "base.html", tdata)
			return
		}
		if warning != nil {
			tdata.ErrorMsg = warning.Error()
		}
		tdata.RegOK = true
	}
	tmpl.ExecuteTemplate(w, "base.html", tdata)
}

func pPersonal(w http.ResponseWriter, r *http.Request) {
	logHTTPRequest(r)
	tmpl, err := config.getTemplate("personal.html", "base.html")
	if err != nil {
		fmt.Println("ERROR loading template:", err)
		return
	}
	tmpl.ExecuteTemplate(w, "base.html", nil)
}

func pOverview(w http.ResponseWriter, r *http.Request) {
	logHTTPRequest(r)
	tmpl, err := config.getTemplate("overview.html", "base.html")
	if err != nil {
		fmt.Println("ERROR loading template:", err)
		return
	}
	tmpl.ExecuteTemplate(w, "base.html", nil)
}

func pUpdating(w http.ResponseWriter, r *http.Request) {
	logHTTPRequest(r)
	tmpl, err := config.getTemplate("updating.html", "base.html")
	if err != nil {
		fmt.Println("ERROR loading template:", err)
		return
	}
	tmpl.ExecuteTemplate(w, "base.html", nil)
}

func getSubmitIP(r *http.Request) string {
	var (
		submitIP string
		err error
	)
	// Used by apache mod_proxy.
	submitIP = r.Header.Get("X-Forwarded-For")
	if len(submitIP) == 0 {
		submitIP, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			submitIP = ""
		}
	}
	return submitIP
}

func pUpdateFromUrl(w http.ResponseWriter, r *http.Request) {
	logHTTPRequest(r)
	vars := mux.Vars(r)
	domain := vars["domain"]
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	if !isValidDomainName(domain) {
		fmt.Fprintf(w, "error: invalid domain")
		return
	}
	submitIP := getSubmitIP(r)
	dstIP, ok := vars["dstIP"]
	if !ok {
		dstIP = submitIP
	}
	if net.ParseIP(dstIP) == nil {
		fmt.Fprintf(w, "error: invalid ip-address %s", dstIP)
		return
	}
	err, warning := updateDomain(domain, dstIP, vars["accesskey"], submitIP)
	if err != nil {
		fmt.Fprintf(w, "error: %s", err.Error())
		return
	}
	if warning != nil {
		fmt.Fprintf(w, "warning: %s", warning.Error())
		return
	}
	fmt.Fprintf(w, "ok %s -> %s", domain, dstIP)
}

func pUpdateFromQueryVars(w http.ResponseWriter, r *http.Request) {
	logHTTPRequest(r)
	vars := r.URL.Query()
	domain := vars.Get("domain")

	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	if !isValidDomainName(domain) {
		fmt.Fprintf(w, "error: invalid domain")
		return
	}
	submitIP := getSubmitIP(r)
	dstIP := vars.Get("dstip")
	if dstIP == "" {
		dstIP = submitIP
	}
	if net.ParseIP(dstIP) == nil {
		fmt.Fprintf(w, "error: invalid ip-address %s", dstIP)
		return
	}
	err, warning := updateDomain(domain, dstIP, vars.Get("accesskey"), submitIP)
	if err != nil {
		fmt.Fprintf(w, "error: %s", err.Error())
		return
	}
	if warning != nil {
		fmt.Fprintf(w, "warning: %s", warning.Error())
		return
	}
	fmt.Fprintf(w, "ok %s -> %s", domain, dstIP)
}

func getBasicAuthInfo(r *http.Request) (string, string) {
	val := r.Header.Get("Authorization")
	if !strings.HasPrefix(val, "Basic ") || len(val) < 7 {
		return "", ""
	}
	val = val[6:]
	data, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return "", ""
	}
	split := strings.Split(string(data), ":")
	if len(split) != 2 {
		return "", ""
	}
	return split[0], split[1]
}

func pUpdateDynDNS(w http.ResponseWriter, r *http.Request) {
	logHTTPRequest(r)
	vars := r.URL.Query()
	domain := vars.Get("hostname")

	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	if !isValidDomainName(domain) {
		fmt.Fprintf(w, "error: invalid domain")
		return
	}
	_, accessKey := getBasicAuthInfo(r)
	submitIP := getSubmitIP(r)
	dstIP := vars.Get("myip")
	if net.ParseIP(dstIP) == nil {
		fmt.Fprintf(w, "error: invalid ip-address %s", dstIP)
		return
	}
	err, _ := updateDomain(domain, dstIP, accessKey, submitIP)
	if err != nil {
		fmt.Fprintf(w, "error: %s", err.Error())
		return
	}
	fmt.Fprintf(w, "good")
}

func pStatic(w http.ResponseWriter, r *http.Request) {
	logHTTPRequest(r)
	vars := mux.Vars(r)
	filename := vars["filename"]
	if strings.Contains(filename, "..") {
		fmt.Fprintf(w, "no")
		return
	}
	filepath := path.Join(config.templatePath, "static", path.Clean(filename))
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		fmt.Fprintf(w, "no")
		return
	}
	ext := path.Ext(filename)
	if ext == ".css" {
		w.Header().Set("Content-Type", "text/css")
	} else if ext == ".js" {
		w.Header().Set("Content-Type", "application/x-javascript")
	}
	w.Write(data)
}

func startHTTPListener(port int) {
	fmt.Printf("Starting HTTP listener on %d\n", port)
	r := mux.NewRouter()
	r.HandleFunc("/", pIndex)
	r.HandleFunc("/personal/", pPersonal)
	r.HandleFunc("/overview/", pOverview)
	r.HandleFunc("/static/{filename}", pStatic)
	r.HandleFunc("/updating/", pUpdating)
	r.HandleFunc("/update", pUpdateFromQueryVars)
	r.HandleFunc("/nic/update", pUpdateDynDNS)
	r.HandleFunc("/update/{domain}/{accesskey}/{dstIP}/", pUpdateFromUrl)
	r.HandleFunc("/update/{domain}/{accesskey}/", pUpdateFromUrl)
	http.Handle("/", r)
	http.ListenAndServe(":"+strconv.Itoa(port), nil)
}

func main() {
	var (
		httpPort = flag.Int("httpport", 8080, "port to use for http queries")
		cSqlHostname = flag.String("sqlhost", sqlHostname, "sql server hostname")
		cSqlUsername = flag.String("sqluser", sqlUsername, "sql server username")
		cSqlPassword = flag.String("sqlpass", sqlPassword, "sql server password")
		cSqlDBName = flag.String("sqldb", sqlDBName, "sql server database name")
		cdnsAPIServers = flag.String("dnsservers", "localhost:8081", "list of space seperated dns:port pairs")
	)
	flag.StringVar(&config.httpApiKey, "httpapikey", "", "key used for communication with dns backend")
	flag.StringVar(&config.templatePath, "tmplpath", "./", "directory that contains the 'templates' and 'static' dirs")
	flag.Parse()
	if config.httpApiKey == "" {
		fmt.Println("ERROR: Missing required flag httpapikey")
		flag.PrintDefaults()
		os.Exit(1)
	}
	config.dnsAPIServers = strings.Split(*cdnsAPIServers, " ")

	err := dbInit(*cSqlHostname, *cSqlUsername, *cSqlPassword, *cSqlDBName)
	if err != nil {
		fmt.Println(err)
		return
	}
	go startHTTPListener(*httpPort)
	fmt.Println("Running")
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
forever:
	for {
		select {
		case s := <-sig:
			fmt.Printf("Signal (%d) received, stopping\n", s)
			break forever
		}
	}
}
