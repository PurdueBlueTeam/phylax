package actions

import (
	"context"
	"errors"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

func TestGuardFromManifest(t *testing.T) {
	m := &manifest.Manifest{
		Accounts: map[string]manifest.Account{
			"alice@ecom": {Username: "alice", Scope: "local", Hosts: []string{"web"}, Scored: manifest.ScoredYes},
			"carol":      {Scope: "local", Hosts: []string{"web"}, Scored: manifest.ScoredUnknown},
			"bob":        {Scope: "local", Hosts: []string{"web"}, Scored: manifest.ScoredNo},
			"dave":       {Scope: "local", Hosts: []string{"db"}, Scored: manifest.ScoredYes},
			"corp\\erin": {Scope: "domain", Scored: manifest.ScoredYes},
		},
		Services: map[string]manifest.Service{
			"web-http": {Host: "web", Scored: true, Process: &manifest.Process{Unit: "httpd.service"},
				Content: &manifest.Content{Roots: []string{"/var/www"}}},
			"web-cron": {Host: "web", Scored: false, Process: &manifest.Process{Unit: "crond.service"}},
			"db-sql":   {Host: "db", Scored: true, Process: &manifest.Process{Unit: "mysqld.service"}},
		},
	}
	g := GuardFromManifest(m, "web")
	ctx := context.Background()
	refused := []Touch{
		{Kind: TouchAccount, Name: "alice", Op: OpLock},
		{Kind: TouchAccount, Name: "carol", Op: OpDelete}, // "protected" counts as scored
		{Kind: TouchAccount, Name: "alice", Op: OpSetPassword},
		{Kind: TouchAccount, Name: "corp\\erin", Op: OpLock},
		{Kind: TouchAccount, Name: "alice", Op: OpRemoveFromGroup, Group: "sudo"},
		{Kind: TouchService, Name: "httpd", Op: OpStop},
		{Kind: TouchPath, Name: "/var/www/index.html", Op: OpModify},
	}
	for _, tc := range refused {
		if err := g.Allow(ctx, tc); !errors.Is(err, ErrScoringUnsafe) {
			t.Errorf("%+v: want refusal, got %v", tc, err)
		}
	}
	allowed := []Touch{
		{Kind: TouchAccount, Name: "bob", Op: OpLock},
		{Kind: TouchAccount, Name: "dave", Op: OpLock}, // scored on another host
		{Kind: TouchAccount, Name: "alice", Op: OpSetPassword, PCR: true},
		{Kind: TouchService, Name: "crond", Op: OpStop},
		{Kind: TouchService, Name: "mysqld", Op: OpStop},
		{Kind: TouchService, Name: "httpd", Op: OpModify},
		{Kind: TouchPath, Name: "/etc/motd", Op: OpModify},
	}
	for _, tc := range allowed {
		if err := g.Allow(ctx, tc); err != nil {
			t.Errorf("%+v: want allowed, got %v", tc, err)
		}
	}
	if GuardFromManifest(nil, "web").Accounts != nil {
		t.Error("nil manifest must give an empty guard")
	}
}
