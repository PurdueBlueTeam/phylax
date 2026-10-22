package report

import (
	"fmt"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/chains"
)

func (b *irBuilder) hasPH(section string) bool {
	for _, p := range b.phs {
		if strings.HasPrefix(p.Section, section) {
			return true
		}
	}
	return false
}

// checklist scores the draft against the WinterKnight and UW-Stout rubrics
// and the playbook's pre-submission list. Each item is Met only when the draft
// itself carries the data; "no partial points" means Partial earns nothing.
func (b *irBuilder) checklist() Checklist {
	in := b.in
	var c Checklist
	add := func(it CheckItem) { c = append(c, it) }

	srcs := b.sources()
	first, access := b.initial()
	haveSrc := len(srcs) > 0

	redFig := false
	for _, f := range b.figs {
		if !f.HasTag(TagRedActivity) {
			continue
		}
		// A pasted excerpt must actually contain a source IP; a screenshot
		// is taken on the operator's word (tag).
		if f.Excerpt == "" {
			redFig = true
			continue
		}
		for _, s := range srcs {
			if strings.Contains(f.Excerpt, s) {
				redFig = true
			}
		}
	}
	hopRefs := access && len(first.h.Evidence) > 0

	// Proof.
	proof := CheckItem{ID: "WK-proof", Rubric: RubricWK, Name: "proof of a red-team compromise (source IP or unmistakable artifact, with a timestamp)", Weight: 10}
	switch {
	case haveSrc && redFig && access:
		proof.Status, proof.Detail = Met, "source IP "+strings.Join(srcs, ", ")+" shown in "+b.tagFigs(TagRedActivity)
	case haveSrc && hopRefs:
		proof.Status, proof.Detail = Partial, "source IP and stored events exist but no figure tagged red_activity shows them; add a log line or screenshot"
	default:
		proof.Status, proof.Detail = Unmet, "no red-team source IP with a figure; add the access-log line"
	}
	add(proof)

	// Time.
	tm := CheckItem{ID: "WK-time", Rubric: RubricWK, Name: "time the compromise happened (timestamp with time zone and how we know)", Weight: 10}
	if !first.h.Start.IsZero() && access {
		tm.Status, tm.Detail = Met, fmt.Sprintf("%s via %s link", Central(first.h.Start), first.h.Method)
	} else if !first.h.Start.IsZero() {
		tm.Status, tm.Detail = Partial, "time is the seed hop, not a confirmed inbound access"
	} else {
		tm.Status, tm.Detail = Unmet, "no initial-access time"
	}
	add(tm)

	// Detection.
	det := CheckItem{ID: "WK-detect", Rubric: RubricWK, Name: "how and when it was detected (tool, log, query)", Weight: 10}
	if in.Detection != nil && !in.Detection.Time.IsZero() && strings.TrimSpace(in.Detection.Method) != "" {
		det.Status, det.Detail = Met, in.Detection.Method
		if b.tagFigs(TagDetection) == "" {
			det.Detail += " (no figure tagged detection; the SIEM/alert screenshot is recommended)"
		}
	} else {
		det.Status, det.Detail = Unmet, "supply the detection time and the tool, log or query"
	}
	add(det)

	// Impact (shared by WK and Stout).
	impactOK := b.hasPH("4. impact") == false && len(b.affectedHosts()) > 0
	imp := func(id, rubric string, w int) CheckItem {
		it := CheckItem{ID: id, Rubric: rubric, Name: "what the attack was and its impact", Weight: w}
		if impactOK {
			it.Status, it.Detail = Met, fmt.Sprintf("%d host(s), %d account(s), downtime stated, data statement made", len(b.affectedHosts()), len(b.accounts()))
		} else {
			it.Status, it.Detail = Unmet, "impact section has placeholders (downtime and the data statement are operator facts)"
		}
		return it
	}
	add(imp("WK-impact", RubricWK, 10))

	// Mitigation.
	mit := CheckItem{ID: "WK-mitigate", Rubric: RubricWK, Name: "how the impact was mitigated (containment shown, not only described)", Weight: 10}
	nContain := len(in.Containment)
	eradItems, eradApplied := 0, 0
	for _, r := range b.hops {
		for _, it := range r.h.Items {
			if eradicationKind(it.Kind) {
				eradItems++
				if it.State != chains.StateOpen && it.State != "" {
					eradApplied++
				}
			}
		}
	}
	switch {
	case nContain > 0 && eradApplied > 0 && b.tagFigs(TagEradication) != "":
		mit.Status, mit.Detail = Met, fmt.Sprintf("%d containment step(s), %d removal item(s) applied, shown in %s", nContain, eradApplied, b.tagFigs(TagEradication))
	case nContain > 0 || eradApplied > 0:
		mit.Status, mit.Detail = Partial, "containment is described but no figure shows the commands (Cedarville lost points for this)"
	default:
		mit.Status, mit.Detail = Unmet, "no containment or removal recorded"
	}
	add(mit)

	// Remediation: the 50%.
	rem := CheckItem{ID: "WK-remediate", Rubric: RubricWK, Name: "the attack path was remediated (retested; if red team returns the same way the 50% is lost)", Weight: 50}
	missing, unverified := 0, 0
	for _, r := range b.hops {
		if !needsRemediation(r.h) {
			continue
		}
		switch {
		case len(r.h.Items) == 0:
			missing++
			rem.Lines = append(rem.Lines, fmt.Sprintf("%s %s: NO remediation item", r.label, r.h.What))
		default:
			st := "verified"
			for _, it := range r.h.Items {
				if !it.Verified() {
					st = "NOT verified (" + it.State + ")"
					unverified++
				}
			}
			rem.Lines = append(rem.Lines, fmt.Sprintf("%s %s: %d item(s), %s", r.label, r.h.What, len(r.h.Items), st))
		}
	}
	retest := len(in.Verification) > 0
	for _, s := range in.Verification {
		if strings.TrimSpace(s.Result) == "" {
			retest = false
		}
	}
	switch {
	case missing == 0 && unverified == 0 && retest && b.tagFigs(TagVerification) != "":
		rem.Status, rem.Detail = Met, "every hop has verified remediation and the retest is recorded with a figure"
	case missing == 0 && unverified == 0 && retest:
		rem.Status, rem.Detail = Partial, "remediation is verified but no figure tagged verification shows the failed retest"
	case missing+unverified > 0:
		rem.Status, rem.Detail = Unmet, fmt.Sprintf("%d hop(s) without a remediation item, %d item(s) not verified", missing, unverified)
	default:
		rem.Status, rem.Detail = Unmet, "items are verified in the controller but the report has no retest step with a result"
	}
	add(rem)

	// Stout rows.
	att := CheckItem{ID: "ST-attack", Rubric: RubricStout, Name: "attack / vulnerability: how they got in, what was left behind, who placed it", Weight: 30}
	hasLeft := false
	for _, r := range b.hops {
		if r.h.Kind == chains.Change {
			hasLeft = true
		}
	}
	switch {
	case access && first.h.Account != "" && b.tagFigs(TagVuln) != "" && hasLeft:
		att.Status, att.Detail = Met, "entry point, account, artifact left behind and the vulnerable-config figure are present"
	case access:
		att.Status = Partial
		var miss []string
		if first.h.Account == "" {
			miss = append(miss, "account used")
		}
		if b.tagFigs(TagVuln) == "" {
			miss = append(miss, "figure of the vulnerable code/config")
		}
		if !hasLeft {
			miss = append(miss, "what was left behind")
		}
		att.Detail = "missing: " + strings.Join(miss, ", ")
	default:
		att.Status, att.Detail = Unmet, "no inbound access hop; the entry point is unknown"
	}
	add(att)

	rm := CheckItem{ID: "ST-remediate", Rubric: RubricStout, Name: "remediation: the fix is shown, not only the finding", Weight: 20}
	if missing == 0 && b.tagFigs(TagRemediation) != "" && unverified == 0 {
		rm.Status, rm.Detail = Met, "all hops have verified items; fix shown in "+b.tagFigs(TagRemediation)
	} else if missing == 0 && b.tagFigs(TagRemediation) != "" {
		rm.Status, rm.Detail = Partial, "fix is shown but some items are not verified"
	} else {
		rm.Status, rm.Detail = Unmet, "need a remediation item for every hop and a figure of the fix"
	}
	add(rm)

	er := CheckItem{ID: "ST-eradicate", Rubric: RubricStout, Name: "eradication: access removed and the artifacts that restart it", Weight: 15}
	persMissing := 0
	for _, r := range b.hops {
		if !r.h.Persistence {
			continue
		}
		ok := false
		for _, it := range r.h.Items {
			if (it.Kind == chains.RemovePersistence || it.Kind == chains.RemoveArtifact) && it.State != chains.StateOpen {
				ok = true
			}
		}
		if !ok {
			persMissing++
			er.Lines = append(er.Lines, fmt.Sprintf("%s persistence %s has no applied removal item", r.label, r.h.Path))
		}
	}
	switch {
	case eradApplied > 0 && persMissing == 0:
		er.Status, er.Detail = Met, fmt.Sprintf("%d removal item(s) applied; every persistence hop covered", eradApplied)
	case eradApplied > 0:
		er.Status, er.Detail = Partial, fmt.Sprintf("%d persistence hop(s) not covered", persMissing)
	default:
		er.Status, er.Detail = Unmet, "no removal item applied"
	}
	add(er)

	add(imp("ST-impact", RubricStout, 10))
	pf := proof
	pf.ID, pf.Rubric = "ST-proof", RubricStout
	add(pf)

	cl := CheckItem{ID: "ST-clarity", Rubric: RubricStout, Name: "clarity: every figure captioned, times with zone, nothing left to fill", Weight: 10}
	var clarity []string
	for _, f := range b.figs {
		if strings.TrimSpace(f.Evidence.Caption) == "" || f.Taken.IsZero() || f.Host == "" {
			clarity = append(clarity, fmt.Sprintf("Figure %d lacks a caption, host or taken-time", f.N))
		}
	}
	if len(b.phs) > 0 {
		clarity = append(clarity, fmt.Sprintf("%d placeholder(s) remain", len(b.phs)))
	}
	if len(clarity) == 0 && len(b.figs) > 0 {
		cl.Status, cl.Detail = Met, "all figures captioned in house format; no placeholders"
	} else {
		cl.Status, cl.Detail, cl.Lines = Unmet, "fix before submitting", clarity
	}
	add(cl)

	gen := CheckItem{ID: "ST-general", Rubric: RubricStout, Name: "general information: source IP, destination IP, port and service, initial-access time, downtime, remediation time, account", Weight: 5}
	var miss []string
	if !haveSrc {
		miss = append(miss, "source IP")
	}
	if len(b.destinations()) == 0 {
		miss = append(miss, "destination IP")
	}
	if len(b.services()) == 0 {
		miss = append(miss, "port and service")
	}
	if in.Downtime == nil {
		miss = append(miss, "downtime")
	}
	if in.RemediationTime.IsZero() {
		miss = append(miss, "remediation timestamp")
	}
	if len(b.accounts()) == 0 {
		miss = append(miss, "account")
	}
	if len(miss) == 0 {
		gen.Status, gen.Detail = Met, "all header rows filled"
	} else {
		gen.Status, gen.Detail = Unmet, "missing: "+strings.Join(miss, ", ")
	}
	add(gen)

	// Playbook list.
	netInvolved := false
	for _, r := range b.hops {
		if isNetworkHop(r.h) {
			netInvolved = true
		}
	}
	fw := CheckItem{ID: "PB-firewall", Rubric: RubricPlaybook, Name: "a firewall log figure for the red-team connection"}
	if !netInvolved || b.tagFigs(TagFirewall) != "" {
		fw.Status, fw.Detail = Met, "present or not applicable"
	} else {
		fw.Status, fw.Detail = Unmet, "add the Palo/FTD log line for the red-team connection (tag: firewall)"
	}
	add(fw)

	tr := CheckItem{ID: "PB-trace", Rubric: RubricPlaybook, Name: "every claim traced to evidence; no unmarked guesses"}
	for _, r := range b.hops {
		if len(r.h.Evidence) == 0 {
			tr.Lines = append(tr.Lines, fmt.Sprintf("%s has no stored-event pointer", r.label))
		}
		if r.h.Method == chains.MethodTimeWindow || r.h.Method == chains.MethodUnmatched || r.h.Confidence < 0.6 {
			tr.Lines = append(tr.Lines, fmt.Sprintf("%s is a guess (%s, %s): the report labels it inferred", r.label, r.h.Method, pct(r.h.Confidence)))
		}
	}
	if len(tr.Lines) == 0 {
		tr.Status, tr.Detail = Met, "every hop has stored events and a confirmed link"
	} else {
		tr.Status, tr.Detail = Partial, "review the hops below"
	}
	add(tr)

	pl := CheckItem{ID: "PB-placeholders", Rubric: RubricPlaybook, Name: "no placeholders left"}
	if len(b.phs) == 0 {
		pl.Status, pl.Detail = Met, "none"
	} else {
		pl.Status, pl.Detail = Unmet, fmt.Sprintf("%d to fill (see the review list)", len(b.phs))
	}
	add(pl)

	add(CheckItem{ID: "PB-tz", Rubric: RubricPlaybook, Name: "timestamps carry a time zone (US Central, UTC alongside)", Status: Met, Detail: "generated in Central with UTC"})
	add(CheckItem{ID: "PB-one-narrative", Rubric: RubricPlaybook, Name: "one report per attack narrative", Status: Met,
		Detail: fmt.Sprintf("%d chain(s) from one campaign / seed set", len(b.cs))})

	shots := CheckItem{ID: "PB-screenshots", Rubric: RubricPlaybook, Name: "screenshots: no cursor, no cropped text, annotated, command and output together", Status: OperatorOnly,
		Detail: "only a human can check this"}
	unconfirmed := 0
	nshots := 0
	for _, f := range b.figs {
		if f.Kind == EvScreenshot || f.Kind == EvFirewall && f.Path != "" {
			nshots++
			if !f.Annotated {
				unconfirmed++
			}
		}
	}
	if nshots > 0 && unconfirmed == 0 {
		shots.Detail = "operator confirmed annotation for every screenshot; still re-read them"
	} else if nshots > 0 {
		shots.Detail = fmt.Sprintf("%d of %d screenshot(s) not yet confirmed annotated", unconfirmed, nshots)
	}
	add(shots)
	add(CheckItem{ID: "PB-red-caused", Rubric: RubricPlaybook, Name: "the incident is red-team-caused: not a preconfigured service, a blocked probe or scorer traffic", Status: OperatorOnly,
		Detail: "confirm with the first-use evidence; a pre-planted item counts only from the first red-team use"})
	add(CheckItem{ID: "PB-header", Rubric: RubricPlaybook, Name: "header re-read by a second person: team number, host, IPs, dates, incident number", Status: OperatorOnly,
		Detail: fmt.Sprintf("incident %d, team %02d, file %s", in.Number, in.Team, mustName(in))})
	return c
}

func mustName(in IRInput) string {
	n, _ := Filename(KindIR, in.Number, in.Team)
	return n
}
