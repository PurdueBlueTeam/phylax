package controller

import (
	"path/filepath"
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	writeFile(t, p, `{"data_dir":"`+dir+`","silence_threshold":"45s"}`)
	c, err := LoadConfig(p)
	if err != nil || time.Duration(c.SilenceThreshold) != 45*time.Second || c.IdentityPath == "" || c.AgentListen == "" {
		t.Fatalf("%+v %v", c, err)
	}
	writeFile(t, p, `{"data_dir":"x","bogus":1}`)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("unknown key accepted")
	}
}
