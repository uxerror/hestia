package selfinstall_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"hestia/internal/proxmox"
)

const (
	apiSecret = "aaaa-bbbb-cccc-dddd-secret-value"
	ctIP      = "198.51.100.7" // documentation range: nothing real is contacted
)

var fixtureDir = filepath.Join("..", "proxmox", "testdata", "real-pve9-selfinstall")

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fakeTask struct {
	kind  string
	fail  string // exit status of a failed task
	polls int
	runs  int // status polls that still answer "running"
}

type fakeCT struct {
	running bool
	form    url.Values
}

// fakePVE is a Proxmox API over TLS built from real PVE 9.2 fixtures; bodies
// are wrapped in {"data": …} and the token header is checked.
type fakePVE struct {
	t    *testing.T
	port int
	fp   string

	mu          sync.Mutex
	extraVMIDs  []int
	tplPresent  bool
	cts         map[int]*fakeCT
	tasks       map[string]*fakeTask
	calls       []string
	createForms []url.Values
	downloaded  []string
	deleted     []string // volumes deleted through the API
	destroyed   []int
	purgeQuery  []string

	failDownload bool
	failStart    bool
	failCreate   bool
	ipAfter      int // interface polls that answer without an address
	noIP         bool
	runsPerTask  int
	ifacePolls   int
	onCreate     func(vmid int)
	taskN        int
}

func newFakePVE(t *testing.T) *fakePVE {
	f := &fakePVE{t: t, tplPresent: true, cts: map[int]*fakeCT{}, tasks: map[string]*fakeTask{}, runsPerTask: 1}
	mux := http.NewServeMux()
	const p = "/api2/json"
	mux.HandleFunc("GET "+p+"/cluster/resources", f.resources)
	mux.HandleFunc("GET "+p+"/nodes/{node}/storage", func(w http.ResponseWriter, r *http.Request) { f.fixture(w, "storage-pve1.json") })
	mux.HandleFunc("GET "+p+"/nodes/{node}/network", func(w http.ResponseWriter, r *http.Request) { f.fixture(w, "network-pve1.json") })
	mux.HandleFunc("GET "+p+"/nodes/{node}/aplinfo", func(w http.ResponseWriter, r *http.Request) { f.fixture(w, "aplinfo.json") })
	mux.HandleFunc("POST "+p+"/nodes/{node}/aplinfo", f.download)
	mux.HandleFunc("GET "+p+"/nodes/{node}/storage/{storage}/content", f.content)
	mux.HandleFunc("DELETE "+p+"/nodes/{node}/storage/{storage}/content/{volume...}", f.deleteVolume)
	mux.HandleFunc("POST "+p+"/nodes/{node}/lxc", f.create)
	mux.HandleFunc("GET "+p+"/nodes/{node}/lxc/{vmid}/status/current", f.status)
	mux.HandleFunc("POST "+p+"/nodes/{node}/lxc/{vmid}/status/start", f.start)
	mux.HandleFunc("POST "+p+"/nodes/{node}/lxc/{vmid}/status/stop", f.stop)
	mux.HandleFunc("DELETE "+p+"/nodes/{node}/lxc/{vmid}", f.destroy)
	mux.HandleFunc("GET "+p+"/nodes/{node}/lxc/{vmid}/config", f.config)
	mux.HandleFunc("GET "+p+"/nodes/{node}/lxc/{vmid}/interfaces", f.interfaces)
	mux.HandleFunc("GET "+p+"/nodes/{node}/tasks/{upid}/status", f.taskStatus)
	mux.HandleFunc("GET "+p+"/nodes/{node}/tasks/{upid}/log", f.taskLog)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "PVEAPIToken=hestia@pve!hestia="+apiSecret {
			http.Error(w, `{"data":null}`, http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h, ps, _ := net.SplitHostPort(srv.Listener.Addr().String())
	f.port, _ = strconv.Atoi(ps)
	fp, err := proxmox.FetchCertFP(context.Background(), h, f.port)
	if err != nil {
		t.Fatal(err)
	}
	f.fp = fp
	return f
}

func (f *fakePVE) called(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (f *fakePVE) data(w http.ResponseWriter, raw string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":` + raw + `}`))
}

func (f *fakePVE) fixture(w http.ResponseWriter, name string) { f.data(w, string(fixture(f.t, name))) }

func (f *fakePVE) fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]any{"data": nil, "message": msg})
	_, _ = w.Write(b)
}

func (f *fakePVE) resources(w http.ResponseWriter, r *http.Request) {
	var res []map[string]any
	_ = json.Unmarshal(fixture(f.t, "cluster-resources.json"), &res)
	f.mu.Lock()
	for _, id := range f.extraVMIDs {
		res = append(res, map[string]any{"type": "lxc", "id": "lxc/" + strconv.Itoa(id), "node": "pve1", "vmid": id, "status": "running", "name": "x"})
	}
	for id := range f.cts {
		res = append(res, map[string]any{"type": "lxc", "id": "lxc/" + strconv.Itoa(id), "node": "pve1", "vmid": id, "status": "stopped", "name": "hestia"})
	}
	f.mu.Unlock()
	b, _ := json.Marshal(res)
	f.data(w, string(b))
}

func (f *fakePVE) newTask(kind, fail string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.taskN++
	upid := "UPID:pve1:0000" + strconv.Itoa(f.taskN) + ":00AA:00BB:" + kind + ":1:hestia@pve!hestia:"
	f.tasks[upid] = &fakeTask{kind: kind, fail: fail, runs: f.runsPerTask}
	return upid
}

func (f *fakePVE) taskStatus(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	tk := f.tasks[r.PathValue("upid")]
	var out map[string]any
	if tk == nil {
		f.mu.Unlock()
		f.fail(w, 500, "no such task")
		return
	}
	tk.polls++
	if tk.polls <= tk.runs {
		out = map[string]any{"status": "running", "type": tk.kind}
	} else {
		ex := "OK"
		if tk.fail != "" {
			ex = tk.fail
		}
		out = map[string]any{"status": "stopped", "exitstatus": ex, "type": tk.kind}
	}
	f.mu.Unlock()
	b, _ := json.Marshal(out)
	f.data(w, string(b))
}

func (f *fakePVE) taskLog(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	tk := f.tasks[r.PathValue("upid")]
	f.mu.Unlock()
	lines := []map[string]any{{"n": 1, "t": "starting task"}}
	if tk != nil && tk.fail != "" {
		lines = append(lines, map[string]any{"n": 2, "t": "TASK ERROR: " + tk.fail})
	} else {
		lines = append(lines, map[string]any{"n": 2, "t": "TASK OK"})
	}
	b, _ := json.Marshal(lines)
	f.data(w, string(b))
}

const tplName = "debian-13-standard_13.6-1_amd64.tar.zst"

func (f *fakePVE) content(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	present := f.tplPresent
	f.mu.Unlock()
	if r.PathValue("storage") == "local" && present {
		f.fixture(w, "storage-local-vztmpl.json")
		return
	}
	f.data(w, "[]")
}

func (f *fakePVE) download(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.PostForm.Get("template") != tplName || r.PostForm.Get("storage") != "local" {
		f.fail(w, 400, "unexpected download request")
		return
	}
	fail := ""
	if f.failDownload {
		fail = "download failed"
	}
	f.mu.Lock()
	f.downloaded = append(f.downloaded, r.PostForm.Get("storage")+":vztmpl/"+r.PostForm.Get("template"))
	if !f.failDownload {
		f.tplPresent = true
	} else {
		f.tplPresent = true // a failed download leaves a partial file behind
	}
	f.mu.Unlock()
	b, _ := json.Marshal(f.newTask("download", fail))
	f.data(w, string(b))
}

func (f *fakePVE) deleteVolume(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.deleted = append(f.deleted, r.PathValue("storage")+"|"+r.PathValue("volume"))
	f.tplPresent = false
	f.mu.Unlock()
	b, _ := json.Marshal(f.newTask("imgdel", ""))
	f.data(w, string(b))
}

func (f *fakePVE) create(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.fail(w, 400, "bad form")
		return
	}
	vmid, _ := strconv.Atoi(r.PostForm.Get("vmid"))
	f.mu.Lock()
	for _, id := range f.extraVMIDs {
		if id == vmid {
			f.mu.Unlock()
			f.fail(w, 500, "CT "+strconv.Itoa(vmid)+" already exists")
			return
		}
	}
	form := url.Values{}
	for k, v := range r.PostForm {
		form[k] = v
	}
	f.createForms = append(f.createForms, form)
	f.cts[vmid] = &fakeCT{form: form}
	cb := f.onCreate
	f.mu.Unlock()
	if cb != nil {
		cb(vmid)
	}
	b, _ := json.Marshal(f.newTask("vzcreate", ""))
	f.data(w, string(b))
}

func (f *fakePVE) ct(w http.ResponseWriter, r *http.Request) (*fakeCT, int) {
	id, _ := strconv.Atoi(r.PathValue("vmid"))
	f.mu.Lock()
	ct := f.cts[id]
	f.mu.Unlock()
	if ct == nil {
		f.fail(w, 500, "Configuration file 'nodes/pve1/lxc/"+r.PathValue("vmid")+".conf' does not exist")
	}
	return ct, id
}

func (f *fakePVE) status(w http.ResponseWriter, r *http.Request) {
	ct, _ := f.ct(w, r)
	if ct == nil {
		return
	}
	f.mu.Lock()
	st := "stopped"
	if ct.running {
		st = "running"
	}
	f.mu.Unlock()
	f.data(w, `{"status":"`+st+`"}`)
}

func (f *fakePVE) start(w http.ResponseWriter, r *http.Request) {
	ct, _ := f.ct(w, r)
	if ct == nil {
		return
	}
	fail := ""
	f.mu.Lock()
	if f.failStart {
		fail = "startup for container failed"
	} else {
		ct.running = true
	}
	f.mu.Unlock()
	b, _ := json.Marshal(f.newTask("vzstart", fail))
	f.data(w, string(b))
}

func (f *fakePVE) stop(w http.ResponseWriter, r *http.Request) {
	ct, _ := f.ct(w, r)
	if ct == nil {
		return
	}
	f.mu.Lock()
	ct.running = false
	f.mu.Unlock()
	b, _ := json.Marshal(f.newTask("vzstop", ""))
	f.data(w, string(b))
}

func (f *fakePVE) destroy(w http.ResponseWriter, r *http.Request) {
	ct, id := f.ct(w, r)
	if ct == nil {
		return
	}
	f.mu.Lock()
	if ct.running {
		f.mu.Unlock()
		f.fail(w, 500, "CT is running")
		return
	}
	f.purgeQuery = append(f.purgeQuery, r.URL.RawQuery)
	f.destroyed = append(f.destroyed, id)
	delete(f.cts, id)
	f.mu.Unlock()
	b, _ := json.Marshal(f.newTask("vzdestroy", ""))
	f.data(w, string(b))
}

func (f *fakePVE) config(w http.ResponseWriter, r *http.Request) {
	ct, _ := f.ct(w, r)
	if ct == nil {
		return
	}
	// The MAC comes from the real config fixture (net0 with hwaddr).
	var cfg map[string]any
	_ = json.Unmarshal(fixture(f.t, "lxc-config-127.json"), &cfg)
	delete(cfg, "description")
	b, _ := json.Marshal(cfg)
	f.data(w, string(b))
}

func (f *fakePVE) interfaces(w http.ResponseWriter, r *http.Request) {
	ct, _ := f.ct(w, r)
	if ct == nil {
		return
	}
	f.mu.Lock()
	f.ifacePolls++
	n := f.ifacePolls
	running := ct.running
	f.mu.Unlock()
	if !running {
		f.fail(w, 500, "container not running")
		return
	}
	ifs := []map[string]any{{"name": "lo", "inet": "127.0.0.1/8"}}
	if !f.noIP && n > f.ipAfter {
		ifs = append(ifs, map[string]any{"name": "eth0", "inet": ctIP + "/24", "hwaddr": "bc:24:11:bc:4c:f6"})
	} else {
		ifs = append(ifs, map[string]any{"name": "eth0"})
	}
	b, _ := json.Marshal(ifs)
	f.data(w, string(b))
}
