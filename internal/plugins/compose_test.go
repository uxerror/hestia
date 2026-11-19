package plugins

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/uxerror/hestia/sdk/rpc"
)

const testDir = "/opt/hestia/7-web"

func TestComposeRejects(t *testing.T) {
	svc := func(body string) string { return `{"services":{"app":{"image":"x",` + body + `}}}` }
	cases := map[string]string{
		"privileged":         svc(`"privileged":true`),
		"privileged str":     svc(`"privileged":"true"`),
		"network host":       svc(`"network_mode":"host"`),
		"network container":  svc(`"network_mode":"container:abc"`),
		"network var":        svc(`"network_mode":"${NET}"`),
		"pid host":           svc(`"pid":"host"`),
		"ipc host":           svc(`"ipc":"host"`),
		"userns":             svc(`"userns_mode":"host"`),
		"uts":                svc(`"uts":"host"`),
		"cgroup host":        svc(`"cgroup":"host"`),
		"cap_add":            svc(`"cap_add":["NET_ADMIN"]`),
		"devices":            svc(`"devices":["/dev/sda:/dev/sda"]`),
		"security_opt":       svc(`"security_opt":["apparmor=unconfined"]`),
		"volumes_from":       svc(`"volumes_from":["other"]`),
		"api socket":         svc(`"use_api_socket":true`),
		"gpus":               svc(`"gpus":"all"`),
		"provider":           svc(`"provider":{"type":"x"}`),
		"bind abs":           svc(`"volumes":["/etc:/host-etc"]`),
		"bind dotdot":        svc(`"volumes":["../8-other:/x"]`),
		"bind home":          svc(`"volumes":["~/x:/x"]`),
		"bind var":           svc(`"volumes":["${HOME}:/x"]`),
		"bind docker sock":   svc(`"volumes":["/var/run/docker.sock:/var/run/docker.sock"]`),
		"bind prefix trick":  svc(`"volumes":["/opt/hestia/7-webx:/x"]`),
		"long bind":          svc(`"volumes":[{"type":"bind","source":"/","target":"/host"}]`),
		"bind project root":  svc(`"volumes":["./:/app"]`),
		"bind project abs":   svc(`"volumes":["/opt/hestia/7-web:/app"]`),
		"bind dot":           svc(`"volumes":[".:/app"]`),
		"bind compose":       svc(`"volumes":["./compose.yaml:/c"]`),
		"bind hestia files":  svc(`"volumes":[{"type":"bind","source":"./.hestia-files","target":"/x"}]`),
		"long npipe":         svc(`"volumes":[{"type":"npipe","source":"x","target":"/x"}]`),
		"env_file outside":   svc(`"env_file":["/etc/shadow"]`),
		"env_file obj":       svc(`"env_file":[{"path":"/root/.env"}]`),
		"build outside":      svc(`"build":{"context":"/"}`),
		"build privileged":   svc(`"build":{"context":".","privileged":true}`),
		"build entitlements": svc(`"build":{"context":".","entitlements":["network.host"]}`),
		"extends file":       svc(`"extends":{"file":"base.yaml","service":"b"}`),
		"hook privileged":    svc(`"post_start":[{"command":"id","privileged":true}]`),
		"reserved devices":   svc(`"deploy":{"resources":{"reservations":{"devices":[{"capabilities":["gpu"]}]}}}`),
		"ports var":          svc(`"ports":["${P}:80"]`),
		"include":            `{"include":["/etc/compose.yaml"],"services":{"app":{"image":"x"}}}`,
		"no services":        `{"services":{}}`,
		"not object":         `["x"]`,
		"yaml":               `services: {}`,
		"bad service name":   `{"services":{"../x":{"image":"x"}}}`,
		"volume driver_opts": `{"services":{"app":{"image":"x"}},"volumes":{"d":{"driver_opts":{"type":"none","o":"bind","device":"/"}}}}`,
		"volume driver":      `{"services":{"app":{"image":"x"}},"volumes":{"d":{"driver":"nfs"}}}`,
		"secret file":        `{"services":{"app":{"image":"x"}},"secrets":{"s":{"file":"/etc/shadow"}}}`,
		"config file":        `{"services":{"app":{"image":"x"}},"configs":{"c":{"file":"../x"}}}`,
		"host network":       `{"services":{"app":{"image":"x"}},"networks":{"n":{"external":true,"name":"host"}}}`,
		"trailing":           `{"services":{"app":{"image":"x"}}} {}`,
	}
	for name, c := range cases {
		_, err := prepareCompose(json.RawMessage(c), testDir, "demo", 7)
		if err == nil || !rpc.IsCode(err, rpc.CodeInvalidParams) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestComposeAccepts(t *testing.T) {
	raw := `{"name":"whatever","services":{
	  "app":{"image":"traefik/whoami:v1.10","command":["--name","hi"],"privileged":false,"network_mode":"bridge",
	    "ports":["8080:80","127.0.0.1:9000-9001:90","5353:53/udp",{"published":"7000","target":70},{"target":71},"[::1]:6000:60"],
	    "volumes":["./data:/data","/opt/hestia/7-web/conf:/conf:ro","named:/v","/anon",{"type":"volume","source":"named","target":"/w"},{"type":"tmpfs","target":"/t"}],
	    "env_file":".env","labels":["a=b","hestia.plugin=evil"],"build":{"context":"./src","dockerfile":"Dockerfile"}},
	  "db":{"image":"postgres","labels":{"x":"y"},"network_mode":"service:app","extends":{"service":"app"}}},
	 "volumes":{"named":{},"other":{"driver":"local"}},
	 "secrets":{"s":{"file":"./secret.txt"}}}`
	pc, err := prepareCompose(json.RawMessage(raw), testDir, "demo", 7)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(pc.services, ",") != "app,db" {
		t.Fatalf("services %v", pc.services)
	}
	if got, _ := json.Marshal(pc.ports); string(got) != "[6000,7000,8080,9000,9001]" {
		t.Fatalf("ports %s", got)
	}
	var out struct {
		Name     *string `json:"name"`
		Services map[string]struct {
			Labels map[string]string `json:"labels"`
		} `json:"services"`
	}
	if err := json.Unmarshal(pc.data, &out); err != nil {
		t.Fatal(err)
	}
	app, db := out.Services["app"].Labels, out.Services["db"].Labels
	if out.Name != nil || app["hestia.plugin"] != "demo" || app["hestia.instance"] != "7" || app["a"] != "b" ||
		db["x"] != "y" || db["hestia.instance"] != "7" {
		t.Fatalf("%s", pc.data)
	}
	// Deterministic output (the plan hash depends on it).
	pc2, _ := prepareCompose(json.RawMessage(raw), testDir, "demo", 7)
	if string(pc2.data) != string(pc.data) {
		t.Fatal("output is not deterministic")
	}
}

func TestMergeFeatures(t *testing.T) {
	cases := []struct{ cur, want string }{
		{"", "keyctl=1,nesting=1"},
		{"nesting=1", "nesting=1,keyctl=1"},
		{"fuse=1,nesting=0", "fuse=1,nesting=1,keyctl=1"},
		{"keyctl=1,nesting=1", "keyctl=1,nesting=1"},
	}
	for _, c := range cases {
		if got := mergeFeatures(c.cur, map[string]string{"nesting": "1", "keyctl": "1"}); got != c.want {
			t.Errorf("%q → %q, want %q", c.cur, got, c.want)
		}
	}
}

func TestParsePSAndSS(t *testing.T) {
	arr := `[{"Name":"a-1","Service":"a","State":"running","Status":"Up","Publishers":[{"URL":"0.0.0.0","TargetPort":80,"PublishedPort":8080,"Protocol":"tcp"},{"TargetPort":81}]}]`
	nd := `{"Name":"b-1","Service":"b","State":"exited","ExitCode":1}` + "\n" + `{"Name":"a-1","Service":"a","State":"running"}` + "\n"
	if cs := parsePS(arr); len(cs) != 1 || len(cs[0].Ports) != 1 || cs[0].Ports[0].PublishedPort != 8080 {
		t.Fatalf("%+v", cs)
	}
	cs := parsePS(nd)
	if len(cs) != 2 || cs[0].Name != "a-1" || cs[1].ExitCode != 1 {
		t.Fatalf("%+v", cs)
	}
	for line, want := range map[string]int{
		"LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:*":    8080,
		"LISTEN 0 4096 [::]:22 [::]:*":            22,
		"LISTEN 0 128 127.0.0.53%lo:53 0.0.0.0:*": 53,
		"garbage": 0,
	} {
		if got := listenPort(line); got != want {
			t.Errorf("%q: %d", line, got)
		}
	}
}
