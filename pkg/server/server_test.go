// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gardener/falco-event-ingestor/pkg/auth"
	"github.com/gardener/falco-event-ingestor/pkg/postgres"
)

var bodyJson []byte

func TestMain(m *testing.M) {
	bodyJson = []byte(`{
    "uuid": "82868906-b4fb-4315-a3a5-8058adb06559",
    "output": "13:28:23.902664502: Notice Unexpected UDP Traffic Seen (connection=100.64.1.8:37092-\u003e100.104.33.120:27017 lport=37092 rport=27017 fd_type=ipv4 fd_proto=fd.l4proto evt_type=connect user=myuser user_uid=10001 user_loginuid=-1 process=user proc_exepath=/user parent=containerd-shim command=user -port=80 terminal=0 exe_flags=\u003cNA\u003e container_id=8ae26c6f57d6 container_image=docker.io/weaveworksdemos/user container_image_tag=0.4.7 container_name=user k8s_ns=sock-shop k8s_pod_name=user-5c8d59bcd4-vbrht)",
    "priority": "Notice",
    "rule": "Unexpected UDP Traffic",
    "time": "2024-02-08T13:28:23.902664502Z",
    "output_fields": {
        "cluster": "falco-test",
        "container.id": "8ae26c6f57d6",
        "container.image.repository": "docker.io/weaveworksdemos/user",
        "container.image.tag": "0.4.7",
        "container.name": "user",
        "evt.arg.flags": null,
        "evt.time": 1707398903902664502,
        "evt.type": "connect",
        "fd.lport": 37092,
        "fd.name": "100.64.1.8:37092-\u003e100.104.33.120:27017",
        "fd.rport": 27017,
        "fd.type": "ipv4",
        "k8s.ns.name": "sock-shop",
        "k8s.pod.name": "user-5c8d59bcd4-vbrht",
        "proc.cmdline": "user -port=80",
        "proc.exepath": "/user",
        "proc.name": "user",
        "proc.pname": "containerd-shim",
        "proc.tty": 0,
        "project": "i573718",
        "user.loginuid": -1,
        "user.name": "myuser",
        "user.uid": 10001
        "cluster_id": "testest"
    },
    "source": "syscall",
    "tags": [
        "TA0011",
        "container",
        "host",
        "maturity_incubating",
        "mitre_exfiltration",
        "network"
    ],
    "hostname": "falco-7pvrx",
}`)
}

func TestTokenEventMatch(t *testing.T) {
	clusterId := "testtest"
	event := &postgres.EventStruct{OutputFields: map[string]json.RawMessage{"output_fields": []byte(clusterId)}}
	token := &auth.TokenValues{ClusterId: clusterId}

	if err := verifyEventTokenMatch(event, token); err != nil {
		t.Fatalf("Mismatch was reported but not present: %s", err.Error())
	}
}

func TestTokenEventMismatch(t *testing.T) {
	clusterId := "testtest"
	event := &postgres.EventStruct{OutputFields: map[string]json.RawMessage{"output_fields": []byte(clusterId)}}
	tokenWrongId := &auth.TokenValues{ClusterId: clusterId + "wrong"}

	if err := verifyEventTokenMatch(event, tokenWrongId); err == nil {
		t.Fatal("Cluster id mismatch was not caught")
	}
}

func TestRequestToEventGood(t *testing.T) {
	bodyReader := strings.NewReader(string(bodyJson[:]))
	req := httptest.NewRequest("GET", "/test", bodyReader)
	if _, err := requestToEvent(req); err != nil {
		t.Fatalf("Good request could not be translated to event: %s", err.Error())
	}
}

func TestRequestToEventUnkownField(t *testing.T) {
	unknownFields := []byte(`, "field": "unknown"`)
	closingBraceIdx := bytes.LastIndexByte(bodyJson, '}')
	unknownFieldsJson := append(bodyJson[:closingBraceIdx], unknownFields...)
	unknownFieldsJson = append(unknownFieldsJson, '}')
	bodyReader := strings.NewReader(string(unknownFieldsJson))
	req := httptest.NewRequest("GET", "/test", bodyReader)
	if _, err := requestToEvent(req); err == nil {
		t.Fatal("Unknown field in request not caught")
	}
}
