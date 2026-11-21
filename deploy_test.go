package main

import (
	"os"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/aviv56470/redactor/internal/redact"
)

// The Kubernetes ConfigMap carries its own copy of rules.yaml. This test fails
// if the two copies ever differ, so the cluster can't silently run with
// different rules from the ones that were tested.
func TestConfigMapMatchesRulesFile(t *testing.T) {
	want, err := os.ReadFile("rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("deploy/kubernetes/configmap.yaml")
	if err != nil {
		t.Fatal(err)
	}

	var configMap struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(raw, &configMap); err != nil {
		t.Fatalf("configmap.yaml is not valid YAML: %v", err)
	}

	got, ok := configMap.Data["rules.yaml"]
	if !ok {
		t.Fatal(`configmap.yaml has no "rules.yaml" entry under data`)
	}
	if got != string(want) {
		t.Error("the rules in deploy/kubernetes/configmap.yaml differ from rules.yaml; copy rules.yaml into it again")
	}
	if _, err := redact.ParseRules([]byte(got)); err != nil {
		t.Errorf("the ConfigMap's rules don't load: %v", err)
	}
}
