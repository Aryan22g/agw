package main

import (
	"strings"
	"testing"
)

func TestWorkloadEnvIsMinimalByDefault(t *testing.T) {
	host := []string{"PATH=/usr/bin", "HOME=/root", "AWS_SECRET_ACCESS_KEY=s3cr3t",
		"GITHUB_TOKEN=ghp_x", "OPENAI_API_KEY=sk-x", "AGW_CHECKPOINT_KEY=/k", "LANG=C.UTF-8"}

	env, err := workloadEnv(host, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	for _, secret := range []string{"s3cr3t", "ghp_x", "sk-x", "AGW_CHECKPOINT_KEY"} {
		if strings.Contains(joined, secret) {
			t.Errorf("%s crossed into the workload by default", secret)
		}
	}
	for _, keep := range []string{"PATH=/usr/bin", "HOME=/root", "LANG=C.UTF-8"} {
		if !strings.Contains(joined, keep) {
			t.Errorf("%s should be passed", keep)
		}
	}

	env, err = workloadEnv(host, []string{"OPENAI_API_KEY", "MODE=eval"}, false)
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(env, "\n")
	if !strings.Contains(joined, "OPENAI_API_KEY=sk-x") || !strings.Contains(joined, "MODE=eval") {
		t.Errorf("explicit grants missing: %v", env)
	}
	if strings.Contains(joined, "s3cr3t") {
		t.Error("granting one variable leaked another")
	}

	if _, err := workloadEnv(host, []string{"NOT_SET"}, false); err == nil {
		t.Error("granting an unset variable should be an error, not a silent omission")
	}

	all, _ := workloadEnv(host, nil, true)
	if len(all) != len(host) {
		t.Error("--inherit-env should pass everything")
	}
}
