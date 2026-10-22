package winevt

import (
	"errors"
	"strings"
	"testing"
)

func TestSnakeCase(t *testing.T) {
	for in, want := range map[string]string{
		"TargetUserName": "target_user_name", "IpAddress": "ip_address", "ObjectDN": "object_dn",
		"AttributeLDAPDisplayName": "attribute_ldap_display_name", "SubjectLogonId": "subject_logon_id",
		"ProcessGUID": "process_guid", "SourceProcessGUID": "source_process_guid", "Hashes": "hashes",
		"Product Name": "product_name", "OriginalFileName": "original_file_name", "DSType": "ds_type",
		"UtcTime": "utc_time", "SHA256": "sha256", "": "",
	} {
		if got := SnakeCase(in); got != want {
			t.Errorf("SnakeCase(%q) = %q want %q", in, got, want)
		}
	}
}

func TestParseSystemFields(t *testing.T) {
	r := loadFixture(t, "sys7045")
	if r.Channel != "System" || r.Provider != "Service Control Manager" || r.EventID != 7045 ||
		r.RecordID != 3001 || r.Computer != "DC01.ccdc.local" || r.PID != 716 || r.UserSID != "S-1-5-21-1-2-3-500" {
		t.Fatalf("%+v", r)
	}
	if r.Time.Format("2006-01-02T15:04:05.000000000Z") != "2026-03-14T18:22:05.123456700Z" {
		t.Fatalf("time = %v", r.Time)
	}
}

func TestParseUnnamedData(t *testing.T) {
	r := loadFixture(t, "sys5829")
	if r.Data["data_1"] != "WKS01$" || r.Data["data_4"] != "10.0.0.99" {
		t.Fatalf("%v", r.Data)
	}
}

func TestParseUserData(t *testing.T) {
	r := loadFixture(t, "sec1102")
	if r.Data["subject_user_name"] != "Administrator" || r.Data["subject_domain_name"] != "CCDC" {
		t.Fatalf("%v", r.Data)
	}
	r = loadFixture(t, "wmi5861")
	if r.Data["namespace"] != "//./root/subscription" || r.Data["possible_cause"] != "Permanent" {
		t.Fatalf("%v", r.Data)
	}
}

func TestMalformedXML(t *testing.T) {
	big := strings.Repeat("a", MaxXMLSize+1)
	for name, in := range map[string]string{
		"empty":       "",
		"truncated":   `<Event xmlns="x"><System><EventID>4624</EventID>`,
		"not-xml":     "garbage \x00\x01",
		"no-eventid":  `<Event><System><Channel>Security</Channel></System></Event>`,
		"bad-eventid": `<Event><System><EventID>abc</EventID></System></Event>`,
		"wrong-root":  `<Foo><System><EventID>1</EventID></System></Foo>`,
		"too-big":     big,
		"empty-event": "<Event/>",
	} {
		_, err := ParseXML([]byte(in))
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestValueTruncationIsBounded(t *testing.T) {
	huge := strings.Repeat("é", 40000)
	x := `<Event><System><EventID>4104</EventID><Channel>c</Channel></System><EventData><Data Name="ScriptBlockText">` + huge +
		`</Data><Data Name="Other">` + huge + `</Data></EventData></Event>`
	r, err := ParseXML([]byte(x))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Data["script_block_text"]) > maxLongValue || len(r.Data["other"]) > maxValue {
		t.Fatalf("sizes %d %d", len(r.Data["script_block_text"]), len(r.Data["other"]))
	}
	if len(r.Truncated) != 2 {
		t.Fatalf("truncated = %v", r.Truncated)
	}
	for _, v := range r.Data {
		if strings.ContainsRune(v, '\uFFFD') {
			t.Fatal("truncation split a rune")
		}
	}
}

func TestQuickRecordID(t *testing.T) {
	if quickRecordID([]byte(`<System><EventRecordID>12345</EventRecordID>`)) != 12345 || quickRecordID([]byte("x")) != 0 {
		t.Fatal("quickRecordID")
	}
}
