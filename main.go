package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	corefile  = "/usr/local/etc/coredns/Corefile"
	coredns   = "/usr/local/bin/coredns"
	zonesDir  = "/usr/local/etc/coredns/zones"
	adminUser = "admin"
	adminPass = "admin"
)

var (
	loginT   = template.Must(template.ParseFiles("templates/login.html"))
	indexT   = template.Must(template.ParseFiles("templates/index.html"))
	zonesT   = template.Must(template.ParseFiles("templates/zones.html"))
	zoneT    = template.Must(template.ParseFiles("templates/zone.html"))
	mu       sync.RWMutex
	sessions = map[string]time.Time{}
	zoneRE   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

type Data struct {
	User, Output, Corefile, Zone, ZoneText, Error string
	Zones                                         []string
}

func token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func passOK(p string) bool {
	a, b := sha256.Sum256([]byte(p)), sha256.Sum256([]byte(adminPass))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
func auth(r *http.Request) bool {
	c, e := r.Cookie("coredns_session")
	if e != nil {
		return false
	}
	mu.RLock()
	x, ok := sessions[c.Value]
	mu.RUnlock()
	return ok && time.Now().Before(x)
}
func protect(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Redirect(w, r, "/login", 303)
			return
		}
		h(w, r)
	}
}
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		_ = loginT.Execute(w, nil)
		return
	}
	if r.FormValue("username") != adminUser || !passOK(r.FormValue("password")) {
		http.Error(w, "Invalid username or password", 401)
		return
	}
	t := token()
	mu.Lock()
	sessions[t] = time.Now().Add(8 * time.Hour)
	mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "coredns_session", Value: t, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 28800})
	http.Redirect(w, r, "/", 303)
}
func logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("coredns_session"); e == nil {
		mu.Lock()
		delete(sessions, c.Value)
		mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "coredns_session", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/login", 303)
}
func run(a ...string) string {
	o, e := exec.Command(a[0], a[1:]...).CombinedOutput()
	s := string(o)
	if e != nil {
		s += "\nERROR: " + e.Error()
	}
	return s
}
func safeZone(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" || !zoneRE.MatchString(s) || strings.Contains(s, "..") || strings.ContainsAny(s, "/\\") {
		return "", os.ErrInvalid
	}
	return strings.ToLower(s), nil
}
func zonePath(z string) (string, error) {
	z, e := safeZone(z)
	if e != nil {
		return "", e
	}
	return filepath.Join(zonesDir, z+".zone"), nil
}
func read(p string) string {
	b, e := os.ReadFile(p)
	if e != nil {
		return "# " + e.Error()
	}
	return string(b)
}
func listZones() []string {
	es, e := os.ReadDir(zonesDir)
	if e != nil {
		return nil
	}
	var r []string
	for _, x := range es {
		if !x.IsDir() && strings.HasSuffix(x.Name(), ".zone") {
			r = append(r, strings.TrimSuffix(x.Name(), ".zone"))
		}
	}
	return r
}
func hostOK(s string) bool {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				return false
			}
		}
	}
	return true
}
func validate(t, n, v, p string) error {
	t = strings.ToUpper(t)
	if strings.TrimSpace(n) == "" || strings.TrimSpace(v) == "" {
		return os.ErrInvalid
	}
	switch t {
	case "A":
		if ip := net.ParseIP(v); ip == nil || ip.To4() == nil {
			return os.ErrInvalid
		}
	case "AAAA":
		if ip := net.ParseIP(v); ip == nil || ip.To4() != nil {
			return os.ErrInvalid
		}
	case "CNAME", "NS", "PTR":
		if !hostOK(v) {
			return os.ErrInvalid
		}
	case "MX":
		q, e := strconv.Atoi(p)
		if e != nil || q < 0 || q > 65535 || !hostOK(v) {
			return os.ErrInvalid
		}
	case "TXT":
	default:
		return os.ErrInvalid
	}
	return nil
}
func header(z string) string {
	return "$ORIGIN " + z + ".\n$TTL 3600\n\n@ IN SOA ns1." + z + ". admin." + z + ". (\n    2026082501\n    3600\n    900\n    604800\n    3600\n)\n\n@ IN NS ns1." + z + ".\n"
}
func ensureBlock(z string) error {
	b, e := os.ReadFile(corefile)
	if e != nil {
		return e
	}
	s := string(b)
	if strings.Contains(s, "# BEGIN ZONE "+z) {
		return nil
	}
	block := "\n# BEGIN ZONE " + z + "\n" + z + " {\n    file " + zonesDir + "/" + z + ".zone\n}\n# END ZONE " + z + "\n"
	_ = os.WriteFile(corefile+".bak", b, 0640)
	return os.WriteFile(corefile, []byte(s+block), 0640)
}
func createZone(w http.ResponseWriter, r *http.Request) {
	z, e := safeZone(r.FormValue("zone"))
	if e != nil {
		http.Error(w, "Invalid zone", 400)
		return
	}
	os.MkdirAll(zonesDir, 0750)
	p, _ := zonePath(z)
	if _, e = os.Stat(p); e == nil {
		http.Error(w, "Zone already exists", 409)
		return
	}
	if e = os.WriteFile(p, []byte(header(z)), 0640); e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	if e = ensureBlock(z); e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	http.Redirect(w, r, "/zone?zone="+template.URLQueryEscaper(z), 303)
}
func saveZone(w http.ResponseWriter, r *http.Request) {
	z, e := safeZone(r.FormValue("zone"))
	if e != nil {
		http.Error(w, "Invalid zone", 400)
		return
	}
	p, _ := zonePath(z)
	text := strings.ReplaceAll(r.FormValue("zonefile"), "\r\n", "\n")
	if strings.TrimSpace(text) == "" {
		http.Error(w, "Zone file is empty", 400)
		return
	}
	if b, e := os.ReadFile(p); e == nil {
		_ = os.WriteFile(p+".bak", b, 0640)
	}
	if e = os.WriteFile(p, []byte(text), 0640); e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	http.Redirect(w, r, "/zone?zone="+template.URLQueryEscaper(z), 303)
}
func addRecord(w http.ResponseWriter, r *http.Request) {
	z, e := safeZone(r.FormValue("zone"))
	if e != nil {
		http.Error(w, "Invalid zone", 400)
		return
	}
	t, n, v, p := r.FormValue("type"), r.FormValue("name"), r.FormValue("value"), r.FormValue("priority")
	if e = validate(t, n, v, p); e != nil {
		http.Error(w, "Invalid record", 400)
		return
	}
	path, _ := zonePath(z)
	if _, e = os.Stat(path); os.IsNotExist(e) {
		os.MkdirAll(zonesDir, 0750)
		os.WriteFile(path, []byte(header(z)), 0640)
	}
	line := n + " IN " + strings.ToUpper(t) + " "
	if strings.ToUpper(t) == "MX" {
		line += p + " "
	}
	if strings.ToUpper(t) == "TXT" {
		v = strings.ReplaceAll(v, `"`, `\"`)
		line += `"` + v + `"`
	} else {
		line += v
	}
	line += "\n"
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0640)
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	defer f.Close()
	f.WriteString(line)
	http.Redirect(w, r, "/zone?zone="+template.URLQueryEscaper(z), 303)
}
func deleteZone(w http.ResponseWriter, r *http.Request) {
	z, e := safeZone(r.FormValue("zone"))
	if e != nil {
		http.Error(w, "Invalid zone", 400)
		return
	}
	p, _ := zonePath(z)
	if e = os.Remove(p); e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	removeBlock(z)
	http.Redirect(w, r, "/zones", 303)
}
func removeBlock(z string) {
	b, e := os.ReadFile(corefile)
	if e != nil {
		return
	}
	s := string(b)
	a, bm := "# BEGIN ZONE "+z, "# END ZONE "+z
	i := strings.Index(s, a)
	if i < 0 {
		return
	}
	j := strings.Index(s[i:], bm)
	if j < 0 {
		return
	}
	j = i + j + len(bm)
	if j < len(s) && s[j] == '\n' {
		j++
	}
	_ = os.WriteFile(corefile+".bak", b, 0640)
	_ = os.WriteFile(corefile, []byte(s[:i]+s[j:]), 0640)
}
func dashboard(w http.ResponseWriter, r *http.Request) {
	_ = indexT.Execute(w, Data{User: adminUser, Corefile: read(corefile)})
}
func action(w http.ResponseWriter, r *http.Request) {
	var o string
	switch r.FormValue("action") {
	case "start":
		o = run("/usr/sbin/service", "coredns", "start")
	case "stop":
		o = run("/usr/sbin/service", "coredns", "stop")
	case "restart":
		o = run("/usr/sbin/service", "coredns", "restart")
	case "status":
		o = run("/usr/sbin/service", "coredns", "status")
	case "validate":
		o = run(coredns, "-conf", corefile, "-dns.port", "0")
	case "reload":
		o = run("/usr/sbin/service", "coredns", "reload")
	case "logs":
		o = run("/usr/bin/tail", "-n", "100", "/var/log/coredns.log")
	}
	_ = indexT.Execute(w, Data{User: adminUser, Corefile: read(corefile), Output: o})
}
func saveCorefile(w http.ResponseWriter, r *http.Request) {
	if e := os.WriteFile(corefile, []byte(r.FormValue("corefile")), 0640); e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	http.Redirect(w, r, "/", 303)
}
func zonesPage(w http.ResponseWriter, r *http.Request) {
	_ = zonesT.Execute(w, Data{User: adminUser, Zones: listZones()})
}
func zonePage(w http.ResponseWriter, r *http.Request) {
	z, e := safeZone(r.URL.Query().Get("zone"))
	d := Data{User: adminUser, Zone: z}
	if e != nil {
		d.Error = "Invalid zone"
	} else {
		p, _ := zonePath(z)
		d.ZoneText = read(p)
	}
	_ = zoneT.Execute(w, d)
}

type PromSample struct {
	Name   string
	Labels map[string]string
	Value  float64
}
type PromStats struct {
	TotalRequests float64            `json:"total_requests"`
	QPS           float64            `json:"qps"`
	RequestTypes  map[string]float64 `json:"request_types"`
	Rcodes        map[string]float64 `json:"rcodes"`
	Zones         map[string]float64 `json:"zones"`
	LatencyMS     float64            `json:"latency_ms"`
	CacheHits     float64            `json:"cache_hits"`
	CacheMisses   float64            `json:"cache_misses"`
	Error         string             `json:"error,omitempty"`
}

var promMu sync.Mutex
var lastPromTotal float64
var lastPromTime time.Time
var lastQPS float64

func parseProm(text string) []PromSample {
	re := regexp.MustCompile(`^([A-Za-z_:][A-Za-z0-9_:]*)(\{([^}]*)\})?\s+([-+0-9.eE]+)$`)
	lr := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)="((?:\\.|[^"])*)"`)
	var out []PromSample
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := re.FindStringSubmatch(line)
		if len(m) != 5 {
			continue
		}
		v, e := strconv.ParseFloat(m[4], 64)
		if e != nil {
			continue
		}
		labels := map[string]string{}
		for _, x := range lr.FindAllStringSubmatch(m[3], -1) {
			labels[x[1]] = strings.ReplaceAll(x[2], `\"`, `"`)
		}
		out = append(out, PromSample{Name: m[1], Labels: labels, Value: v})
	}
	return out
}
func scrapeCoreDNSMetrics() (PromStats, error) {
	addr := os.Getenv("COREDNS_PROMETHEUS_URL")
	if addr == "" {
		addr = "http://127.0.0.1:9153/metrics"
	}
	if _, e := url.ParseRequestURI(addr); e != nil {
		return PromStats{}, e
	}
	resp, e := (&http.Client{Timeout: 5 * time.Second}).Get(addr)
	if e != nil {
		return PromStats{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return PromStats{}, fmt.Errorf("metrics endpoint returned HTTP %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if e != nil {
		return PromStats{}, e
	}
	st := PromStats{RequestTypes: map[string]float64{}, Rcodes: map[string]float64{}, Zones: map[string]float64{}}
	var ls, lc float64
	for _, x := range parseProm(string(b)) {
		switch x.Name {
		case "coredns_dns_requests_total":
			st.TotalRequests += x.Value
			if v := x.Labels["type"]; v != "" {
				st.RequestTypes[v] += x.Value
			}
			if v := x.Labels["zone"]; v != "" {
				st.Zones[v] += x.Value
			}
		case "coredns_dns_responses_total":
			if v := x.Labels["rcode"]; v != "" {
				st.Rcodes[v] += x.Value
			}
		case "coredns_dns_request_duration_seconds_sum":
			ls += x.Value
		case "coredns_dns_request_duration_seconds_count":
			lc += x.Value
		case "coredns_cache_hits_total":
			st.CacheHits += x.Value
		case "coredns_cache_misses_total":
			st.CacheMisses += x.Value
		}
	}
	if lc > 0 {
		st.LatencyMS = ls / lc * 1000
	}
	promMu.Lock()
	now := time.Now()
	if !lastPromTime.IsZero() {
		dt := now.Sub(lastPromTime).Seconds()
		if dt > 0 && st.TotalRequests >= lastPromTotal {
			lastQPS = (st.TotalRequests - lastPromTotal) / dt
		}
	}
	lastPromTotal = st.TotalRequests
	lastPromTime = now
	st.QPS = lastQPS
	promMu.Unlock()
	return st, nil
}
func statsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	st, e := scrapeCoreDNSMetrics()
	if e != nil {
		st.Error = e.Error()
	}
	_ = json.NewEncoder(w).Encode(st)
}

func main() {
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", protect(logout))
	http.HandleFunc("/", protect(dashboard))
	http.HandleFunc("/action", protect(action))
	http.HandleFunc("/save", protect(saveCorefile))
	http.HandleFunc("/zones", protect(zonesPage))
	http.HandleFunc("/zone", protect(zonePage))
	http.HandleFunc("/zones/create", protect(createZone))
	http.HandleFunc("/zones/save", protect(saveZone))
	http.HandleFunc("/zones/record/add", protect(addRecord))
	http.HandleFunc("/zones/delete", protect(deleteZone))
	http.HandleFunc("/api/stats", protect(statsAPI))
	log.Println("CoreDNS Manager listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
