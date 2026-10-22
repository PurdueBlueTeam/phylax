package deadman

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

// Schtasks arms a Windows scheduled task through schtasks.exe. The task runs as
// SYSTEM, once, at the deadline (second precision, via task XML), and is owned
// by the Task Scheduler service, so it fires if the agent dies. schtasks.exe is
// used instead of the Task Scheduler COM API to avoid a COM dependency in the
// critical path; the XML it consumes is the same schema COM registers.
type Schtasks struct {
	Command Command
	// Folder is the task folder, default `\Phylax`.
	Folder string
	Run    Runner
	Now    func() time.Time
	// TempDir is where the task XML is staged (default os.TempDir()).
	TempDir string
}

// TaskName is the full task path for an entry id.
func (s *Schtasks) TaskName(id string) string {
	f := s.Folder
	if f == "" {
		f = `\Phylax`
	}
	return strings.TrimRight(f, `\`) + `\Deadman-` + id
}

func (s *Schtasks) run() Runner {
	if s.Run != nil {
		return s.Run
	}
	return ExecRunner
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// quoteWinArg quotes one argument for the Task Scheduler <Arguments> field.
func quoteWinArg(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\"") {
		return a
	}
	return `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
}

// TaskXML renders the task definition (exported for tests and inspection).
func (s *Schtasks) TaskXML(id string, deadline time.Time) (string, error) {
	cmd, err := s.Command.resolve()
	if err != nil {
		return "", err
	}
	argv := cmd.argv(id)
	var args []string
	for _, a := range argv[1:] {
		args = append(args, quoteWinArg(a))
	}
	start := deadline.Local().Format("2006-01-02T15:04:05")
	end := deadline.Local().Add(24 * time.Hour).Format("2006-01-02T15:04:05")
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Phylax dead-man rollback %s</Description></RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>%s</StartBoundary>
      <EndBoundary>%s</EndBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <DeleteExpiredTaskAfter>PT1H</DeleteExpiredTaskAfter>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>%s</Command><Arguments>%s</Arguments></Exec>
  </Actions>
</Task>
`, xmlEscape(id), start, end, xmlEscape(argv[0]), xmlEscape(strings.Join(args, " "))), nil
}

func utf16leWithBOM(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2, 2+2*len(u))
	b[0], b[1] = 0xFF, 0xFE
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

func (s *Schtasks) Arm(ctx context.Context, id string, deadline time.Time) error {
	if !ValidID(id) {
		return ErrBadID
	}
	x, err := s.TaskXML(id, deadline)
	if err != nil {
		return err
	}
	dir := s.TempDir
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.CreateTemp(dir, "phylax-deadman-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, werr := f.Write(utf16leWithBOM(x))
	cerr := f.Close()
	if werr != nil || cerr != nil {
		return fmt.Errorf("stage task xml: %v %v", werr, cerr)
	}
	// /F replaces an existing task of the same name (re-arm after restart).
	_, err = s.run()(ctx, "schtasks.exe", "/Create", "/TN", s.TaskName(id), "/XML", filepath.Clean(f.Name()), "/F")
	return err
}

func (s *Schtasks) Disarm(ctx context.Context, id string) error {
	if !ValidID(id) {
		return ErrBadID
	}
	out, err := s.run()(ctx, "schtasks.exe", "/Delete", "/TN", s.TaskName(id), "/F")
	if err != nil {
		low := strings.ToLower(string(out) + err.Error())
		if strings.Contains(low, "cannot find") || strings.Contains(low, "does not exist") {
			return nil
		}
		return err
	}
	return nil
}
