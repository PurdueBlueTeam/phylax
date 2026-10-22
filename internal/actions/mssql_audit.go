package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Read-only SQL Server state, shared by mssql.audit, the sql.query named
// statements and mssql.lock. The statement text is shared with the in-memory
// fake in tests.
const (
	mssqlSelfSQL = "SELECT CAST(SUSER_SNAME() AS NVARCHAR(256)), CAST(IS_SRVROLEMEMBER('sysadmin') AS INT)"

	mssqlVersionSQL = "SELECT CAST(@@VERSION AS NVARCHAR(512)) AS version, " +
		"CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(64)) AS product_version, " +
		"CAST(SERVERPROPERTY('ProductLevel') AS NVARCHAR(64)) AS product_level, " +
		"ISNULL(CAST(SERVERPROPERTY('ProductUpdateLevel') AS NVARCHAR(64)),'') AS update_level, " +
		"CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128)) AS edition, " +
		"CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS INT) AS windows_auth_only"

	mssqlSysadminsSQL = "SELECT CAST(m.name AS NVARCHAR(256)) AS name, CAST(m.type AS NVARCHAR(4)) AS type, CAST(m.is_disabled AS INT) AS is_disabled " +
		"FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id=rm.role_principal_id " +
		"JOIN sys.server_principals m ON m.principal_id=rm.member_principal_id WHERE r.name='sysadmin' ORDER BY m.name"

	// Weak-password policy check: a fixed comparison of the stored hash with
	// the empty password and with the login name. It never tries any other
	// candidate (no guessing, no brute force).
	mssqlLoginsSQL = "SELECT CAST(p.name AS NVARCHAR(256)) AS name, CAST(p.type AS NVARCHAR(4)) AS type, CAST(p.is_disabled AS INT) AS is_disabled, " +
		"ISNULL(CAST(l.is_policy_checked AS INT),-1) AS policy_checked, ISNULL(CAST(l.is_expiration_checked AS INT),-1) AS expiration_checked, " +
		"CASE WHEN l.principal_id IS NULL THEN -1 WHEN l.password_hash IS NULL THEN 1 WHEN PWDCOMPARE('', l.password_hash)=1 THEN 1 ELSE 0 END AS blank_password, " +
		"CASE WHEN l.principal_id IS NULL OR l.password_hash IS NULL THEN -1 WHEN PWDCOMPARE(p.name, l.password_hash)=1 THEN 1 ELSE 0 END AS password_is_name " +
		"FROM sys.server_principals p LEFT JOIN sys.sql_logins l ON l.principal_id=p.principal_id " +
		"WHERE p.type IN ('S','U','G') AND p.name NOT LIKE '##%' ORDER BY p.name"

	mssqlConfigSQL = "SELECT CAST(name AS NVARCHAR(128)) AS name, CAST(value_in_use AS INT) AS value_in_use, CAST(value AS INT) AS value " +
		"FROM sys.configurations WHERE name IN ('xp_cmdshell','Ole Automation Procedures','clr enabled','clr strict security'," +
		"'external scripts enabled','Ad Hoc Distributed Queries','show advanced options','scan for startup procs'," +
		"'cross db ownership chaining','remote access','Database Mail XPs','Agent XPs') ORDER BY name"

	mssqlLinkedSQL = "SELECT CAST(s.name AS NVARCHAR(256)) AS name, ISNULL(CAST(s.product AS NVARCHAR(128)),'') AS product, " +
		"ISNULL(CAST(s.provider AS NVARCHAR(128)),'') AS provider, ISNULL(CAST(s.data_source AS NVARCHAR(512)),'') AS data_source, " +
		"CAST(s.is_rpc_out_enabled AS INT) AS rpc_out, CAST(s.is_data_access_enabled AS INT) AS data_access, " +
		"ISNULL((SELECT STRING_AGG(CONCAT(ISNULL(SUSER_NAME(ll.local_principal_id),'*'),'->',ISNULL(ll.remote_name,'(self)')),';') " +
		"FROM sys.linked_logins ll WHERE ll.server_id=s.server_id),'') AS logins " +
		"FROM sys.servers s WHERE s.is_linked=1 ORDER BY s.name"

	mssqlJobsSQL = "SELECT CAST(j.name AS NVARCHAR(256)) AS job, ISNULL(CAST(SUSER_SNAME(j.owner_sid) AS NVARCHAR(256)),'?') AS owner, " +
		"CAST(j.enabled AS INT) AS enabled, ISNULL(s.step_id,0) AS step, ISNULL(CAST(s.subsystem AS NVARCHAR(64)),'') AS subsystem, " +
		"ISNULL(CAST(s.database_name AS NVARCHAR(256)),'') AS db, ISNULL(LEFT(CAST(s.command AS NVARCHAR(MAX)),300),'') AS command " +
		"FROM msdb.dbo.sysjobs j LEFT JOIN msdb.dbo.sysjobsteps s ON s.job_id=j.job_id ORDER BY j.name, s.step_id"

	mssqlStartupSQL = "SELECT CAST(name AS NVARCHAR(256)) AS name FROM master.sys.procedures WHERE OBJECTPROPERTY(object_id,'ExecIsStartup')=1 ORDER BY name"

	mssqlTrustSQL = "SELECT CAST(d.name AS NVARCHAR(256)) AS name, ISNULL(CAST(SUSER_SNAME(d.owner_sid) AS NVARCHAR(256)),'?') AS owner, " +
		"ISNULL(CAST(IS_SRVROLEMEMBER('sysadmin', SUSER_SNAME(d.owner_sid)) AS INT),0) AS owner_is_sysadmin " +
		"FROM sys.databases d WHERE d.is_trustworthy_on=1 AND d.name<>'msdb' ORDER BY d.name"

	mssqlTriggersSQL = "SELECT CAST(t.name AS NVARCHAR(256)) AS name, CAST(t.is_disabled AS INT) AS is_disabled, " +
		"ISNULL(LEFT(OBJECT_DEFINITION(t.object_id),300),'') AS definition FROM sys.server_triggers t ORDER BY t.name"
)

// sp_configure option names this package manages, by short feature name.
var mssqlFeatures = map[string]string{
	"xp_cmdshell":               "xp_cmdshell",
	"ole_automation":            "Ole Automation Procedures",
	"clr":                       "clr enabled",
	"external_scripts":          "external scripts enabled",
	"adhoc_distributed_queries": "Ad Hoc Distributed Queries",
}

var mssqlDefaultFeatures = []string{"xp_cmdshell", "ole_automation", "clr"}

func mssqlFeatureNames() []string {
	var n []string
	for k := range mssqlFeatures {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

type mssqlPrincipal struct {
	Name         string `json:"name"`
	Type         string `json:"type"` // S sql login, U windows login, G windows group
	Disabled     bool   `json:"disabled"`
	PolicyChk    int    `json:"policy_checked"`
	ExpirationCk int    `json:"expiration_checked"`
	BlankPW      bool   `json:"blank_password,omitempty"`
	NamePW       bool   `json:"password_is_name,omitempty"`
}

type mssqlLinked struct {
	Name, Product, Provider, DataSource, Logins string
	RPCOut                                      bool
}

type mssqlJobStep struct {
	Job, Owner, Subsystem, DB, Command string
	Enabled                            bool
	Step                               int
}

type mssqlTrust struct {
	DB, Owner string
	OwnerSA   bool
}

type mssqlTrigger struct {
	Name, Def string
	Disabled  bool
}

// mssqlState is a full read-only snapshot.
type mssqlState struct {
	Version, ProductVersion, ProductLevel, UpdateLevel, Edition string
	WindowsAuthOnly                                             bool
	Self                                                        string
	SelfSysadmin                                                bool
	Logins                                                      []mssqlPrincipal
	Sysadmins                                                   []mssqlPrincipal // type/disabled from server_principals
	Config                                                      map[string]int   // value_in_use
	Linked                                                      []mssqlLinked
	Jobs                                                        []mssqlJobStep
	JobsErr                                                     string
	Startup                                                     []string
	Trust                                                       []mssqlTrust
	Triggers                                                    []mssqlTrigger
}

func atoi(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }

func shape(r *MSSQLResult, n int, what string) error {
	for _, row := range r.Rows {
		if len(row) < n {
			return fmt.Errorf("unexpected %s row shape", what)
		}
	}
	return nil
}

func mssqlRead(ctx context.Context, c MSSQLConn) (*mssqlState, error) {
	st := &mssqlState{Config: map[string]int{}}
	q := func(sql, what string, n int) (*MSSQLResult, error) {
		r, err := c.Query(ctx, sql)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		return r, shape(r, n, what)
	}
	r, err := q(mssqlSelfSQL, "identity", 2)
	if err != nil || len(r.Rows) != 1 {
		return nil, fmt.Errorf("identity query: %v", err)
	}
	st.Self, st.SelfSysadmin = r.Rows[0][0], r.Rows[0][1] == "1"
	if r, err = q(mssqlVersionSQL, "version", 6); err != nil || len(r.Rows) != 1 {
		return nil, fmt.Errorf("version query: %v", err)
	}
	v := r.Rows[0]
	st.Version, st.ProductVersion, st.ProductLevel, st.UpdateLevel, st.Edition = v[0], v[1], v[2], v[3], v[4]
	st.WindowsAuthOnly = v[5] == "1"

	if r, err = q(mssqlLoginsSQL, "logins", 7); err != nil {
		return nil, err
	}
	for _, row := range r.Rows {
		st.Logins = append(st.Logins, mssqlPrincipal{Name: row[0], Type: row[1], Disabled: row[2] == "1",
			PolicyChk: atoi(row[3]), ExpirationCk: atoi(row[4]), BlankPW: row[5] == "1", NamePW: row[6] == "1"})
	}
	if r, err = q(mssqlSysadminsSQL, "sysadmins", 3); err != nil {
		return nil, err
	}
	for _, row := range r.Rows {
		st.Sysadmins = append(st.Sysadmins, mssqlPrincipal{Name: row[0], Type: row[1], Disabled: row[2] == "1"})
	}
	if r, err = q(mssqlConfigSQL, "configuration", 3); err != nil {
		return nil, err
	}
	for _, row := range r.Rows {
		st.Config[row[0]] = atoi(row[1])
	}
	if r, err = q(mssqlLinkedSQL, "linked servers", 7); err != nil {
		return nil, err
	}
	for _, row := range r.Rows {
		st.Linked = append(st.Linked, mssqlLinked{Name: row[0], Product: row[1], Provider: row[2], DataSource: row[3], RPCOut: row[4] == "1", Logins: row[6]})
	}
	if r, err = c.Query(ctx, mssqlJobsSQL); err != nil {
		st.JobsErr = err.Error() // msdb absent (Express) or no rights: not fatal
	} else if err = shape(r, 7, "agent jobs"); err != nil {
		return nil, err
	} else {
		for _, row := range r.Rows {
			st.Jobs = append(st.Jobs, mssqlJobStep{Job: row[0], Owner: row[1], Enabled: row[2] == "1", Step: atoi(row[3]), Subsystem: row[4], DB: row[5], Command: row[6]})
		}
	}
	if r, err = q(mssqlStartupSQL, "startup procedures", 1); err != nil {
		return nil, err
	}
	for _, row := range r.Rows {
		st.Startup = append(st.Startup, row[0])
	}
	if r, err = q(mssqlTrustSQL, "trustworthy databases", 3); err != nil {
		return nil, err
	}
	for _, row := range r.Rows {
		st.Trust = append(st.Trust, mssqlTrust{DB: row[0], Owner: row[1], OwnerSA: row[2] == "1"})
	}
	if r, err = q(mssqlTriggersSQL, "server triggers", 3); err != nil {
		return nil, err
	}
	for _, row := range r.Rows {
		st.Triggers = append(st.Triggers, mssqlTrigger{Name: row[0], Disabled: row[1] == "1", Def: row[2]})
	}
	return st, nil
}

// mssqlBuildOutdated reports whether a SQL Server 2019 build is below the
// fixed builds of the September 2026 remote-code-execution fixes (GDR family
// 15.0.2000-3999 fixed at 15.0.2190.7, CU family from 15.0.4000 fixed at
// 15.0.4490.9). Other majors return false (unknown).
func mssqlBuildOutdated(pv string) bool {
	parts := strings.Split(pv, ".")
	if len(parts) < 3 || atoi(parts[0]) != 15 || atoi(parts[1]) != 0 {
		return false
	}
	build, rev := atoi(parts[2]), 0
	if len(parts) > 3 {
		rev = atoi(parts[3])
	}
	switch {
	case build < 4000:
		return build < 2190 || (build == 2190 && rev < 7)
	default:
		return build < 4490 || (build == 4490 && rev < 9)
	}
}

func mssqlSystemPrincipal(n string) bool {
	u := strings.ToUpper(n)
	return strings.HasPrefix(u, "NT SERVICE\\") || strings.HasPrefix(u, "NT AUTHORITY\\") || strings.HasPrefix(n, "##")
}

var mssqlRiskyStepSubsystems = map[string]bool{"CmdExec": true, "PowerShell": true, "ActiveScripting": true}

func mssqlAuditState(st *mssqlState) []dbFinding {
	var out []dbFinding
	add := func(sev, acct, issue string) { out = append(out, dbFinding{sev, acct, issue}) }
	if mssqlBuildOutdated(st.ProductVersion) {
		add("warning", "server", "build "+st.ProductVersion+" is below the fixed builds 15.0.2190.7 (GDR) / 15.0.4490.9 (CU) for the Sept 2026 unauthenticated RCEs")
	}
	cfg := func(k string) bool { return st.Config[k] == 1 }
	if cfg("xp_cmdshell") {
		add("critical", "config", "xp_cmdshell is enabled (OS commands as the service account)")
	}
	if cfg("Ole Automation Procedures") {
		add("critical", "config", "Ole Automation Procedures are enabled")
	}
	if cfg("clr enabled") {
		add("warning", "config", "CLR is enabled")
		if v, ok := st.Config["clr strict security"]; ok && v == 0 {
			add("warning", "config", "CLR strict security is off")
		}
	}
	if cfg("external scripts enabled") {
		add("warning", "config", "external scripts are enabled")
	}
	if cfg("Ad Hoc Distributed Queries") {
		add("warning", "config", "Ad Hoc Distributed Queries are enabled")
	}
	if cfg("cross db ownership chaining") {
		add("warning", "config", "cross-database ownership chaining is on")
	}
	if cfg("scan for startup procs") {
		add("warning", "config", "startup procedures are scanned at start")
	}
	sa := map[string]bool{}
	for _, m := range st.Sysadmins {
		sa[strings.ToLower(m.Name)] = true
		if mssqlSystemPrincipal(m.Name) || m.Disabled || strings.EqualFold(m.Name, st.Self) {
			continue
		}
		sev := "warning"
		if strings.EqualFold(m.Name, "sa") {
			sev = "info"
		}
		add(sev, m.Name, "member of sysadmin")
	}
	for _, l := range st.Logins {
		if l.Disabled || mssqlSystemPrincipal(l.Name) {
			continue
		}
		if l.BlankPW {
			add("critical", l.Name, "blank password")
		}
		if l.NamePW {
			add("critical", l.Name, "password equals the login name")
		}
		if l.Type == "S" && l.PolicyChk == 0 {
			add("info", l.Name, "password policy not enforced (CHECK_POLICY off)")
		}
		if l.Type == "S" && strings.EqualFold(l.Name, "sa") {
			add("warning", l.Name, "sa is enabled")
		}
	}
	for _, s := range st.Linked {
		sev := "warning"
		if s.RPCOut {
			add(sev, s.Name, "linked server with RPC out ("+s.Provider+" "+s.DataSource+"; logins "+s.Logins+")")
		} else {
			add(sev, s.Name, "linked server ("+s.Provider+" "+s.DataSource+"; logins "+s.Logins+")")
		}
	}
	seen := map[string]bool{}
	for _, j := range st.Jobs {
		if mssqlRiskyStepSubsystems[j.Subsystem] && j.Enabled {
			add("warning", "job "+j.Job, fmt.Sprintf("step %d runs %s as %s: %s", j.Step, j.Subsystem, j.Owner, truncate(j.Command, 120)))
		}
		if !seen[j.Job] && j.Enabled && !strings.EqualFold(j.Owner, "sa") && !sa[strings.ToLower(j.Owner)] {
			seen[j.Job] = true
			add("info", "job "+j.Job, "owned by "+j.Owner)
		}
	}
	for _, p := range st.Startup {
		add("warning", "master."+p, "startup procedure")
	}
	for _, t := range st.Trust {
		sev := "warning"
		if t.OwnerSA {
			sev = "critical"
		}
		add(sev, t.DB, "TRUSTWORTHY is on (owner "+t.Owner+")")
	}
	for _, t := range st.Triggers {
		if !t.Disabled {
			add("warning", t.Name, "server-level trigger: "+truncate(t.Def, 120))
		}
	}
	rank := map[string]int{"critical": 0, "warning": 1, "info": 2}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] < rank[out[j].Severity] })
	return out
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// ---- mssql.audit ----

type mssqlAudit struct{}

func (mssqlAudit) Spec() Spec {
	return Spec{Name: "mssql.audit", Risk: RiskNone, ReadOnly: true,
		Doc: "Audit the local SQL Server (integrated auth on Windows, else the vault SQL login): version and patch level, sysadmin members, " +
			"blank / same-as-name password logins (a fixed policy check of two candidates, never guessing), xp_cmdshell / OLE / CLR / external scripts, " +
			"linked servers, SQL Agent jobs and owners, startup procedures, TRUSTWORTHY databases, server triggers. fail_on_critical fails the node on critical findings.",
		Params: []ParamSpec{mssqlServerParam, mssqlPortParam, {Name: "fail_on_critical", Type: Bool}}}
}
func (mssqlAudit) Locks(Params) []string  { return nil }
func (mssqlAudit) Touches(Params) []Touch { return nil }
func (mssqlAudit) Plan(context.Context, *Env, Params) (Plan, error) {
	return Plan{Diff: "read-only"}, nil
}
func (mssqlAudit) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }
func (mssqlAudit) Verify(context.Context, *Env, Params) error              { return nil }

func (mssqlAudit) Apply(ctx context.Context, _ *Env, p Params) (Output, error) {
	c, _, err := mssqlConnect(ctx, p)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	st, err := mssqlRead(ctx, c)
	if err != nil {
		return nil, err
	}
	fs := mssqlAuditState(st)
	crit := 0
	var lines []string
	for _, f := range fs {
		if f.Severity == "critical" {
			crit++
		}
		lines = append(lines, f.Severity+" "+f.Account+": "+f.Issue)
	}
	b, _ := json.Marshal(fs)
	out := Output{"server_version": st.ProductVersion, "product_level": st.ProductLevel, "update_level": st.UpdateLevel,
		"edition": st.Edition, "connected_as": st.Self, "logins": fmt.Sprint(len(st.Logins)), "sysadmins": fmt.Sprint(len(st.Sysadmins)),
		"critical": fmt.Sprint(crit), "findings": strings.Join(lines, "\n"), "findings_json": string(b)}
	if st.JobsErr != "" {
		out["agent_jobs_error"] = st.JobsErr
	}
	if crit > 0 && p.Bool("fail_on_critical") {
		return out, fmt.Errorf("%d critical finding(s)", crit)
	}
	return out, nil
}

// ---- named statements for sql.query ----

var mssqlNamed = map[string][]string{
	"version":                              {mssqlVersionSQL},
	"sysadmins":                            {mssqlSysadminsSQL},
	"review_sysadmins":                     {mssqlSysadminsSQL},
	"logins":                               {mssqlLoginsSQL},
	"weak_logins":                          {mssqlLoginsSQL}, // filtered below
	"config":                               {mssqlConfigSQL},
	"linked_servers":                       {mssqlLinkedSQL},
	"agent_jobs":                           {mssqlJobsSQL},
	"review_linked_servers_and_agent_jobs": {mssqlLinkedSQL, mssqlJobsSQL},
	"startup_procs":                        {mssqlStartupSQL},
	"trustworthy_dbs":                      {mssqlTrustSQL},
	"server_triggers":                      {mssqlTriggersSQL},
	"audit":                                nil,
}

func mssqlNamedList() []string {
	var n []string
	for k := range mssqlNamed {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func renderMSSQL(r *MSSQLResult) string {
	var b strings.Builder
	b.WriteString(strings.Join(r.Columns, "\t") + "\n")
	for i, row := range r.Rows {
		if i >= 200 {
			b.WriteString("...\n")
			break
		}
		b.WriteString(strings.Join(row, "\t") + "\n")
	}
	return b.String()
}

func mssqlRunNamed(ctx context.Context, c MSSQLConn, env *Env, name string) (Output, error) {
	if name == "audit" {
		st, err := mssqlRead(ctx, c)
		if err != nil {
			return nil, err
		}
		var lines []string
		for _, f := range mssqlAuditState(st) {
			lines = append(lines, f.Severity+" "+f.Account+": "+f.Issue)
		}
		return Output{"server_version": st.ProductVersion, "findings": strings.Join(lines, "\n")}, nil
	}
	out := Output{}
	var all strings.Builder
	rows := 0
	for i, q := range mssqlNamed[name] {
		r, err := c.Query(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if name == "weak_logins" {
			f := r.Rows[:0:0]
			for _, row := range r.Rows {
				if len(row) >= 7 && (row[5] == "1" || row[6] == "1") {
					f = append(f, row)
				}
			}
			r.Rows = f
		}
		rows += len(r.Rows)
		if i > 0 {
			all.WriteString("\n")
		}
		all.WriteString(renderMSSQL(r))
		if name == "version" && len(r.Rows) == 1 && len(r.Rows[0]) >= 2 {
			out["version"], out["product_version"] = r.Rows[0][0], r.Rows[0][1]
		}
	}
	out["rows"], out["result"] = fmt.Sprint(rows), all.String()
	return out, nil
}
