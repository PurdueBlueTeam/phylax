package bench

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func rec(sec int, mark string) Record {
	return Record{T: time.Unix(1700000000+int64(sec), 0).UTC(), Kind: KindMark, Mark: mark}
}

func TestLogRoundTrip(t *testing.T) {
	t.Skip("unimplemented: W14 Task 3")
	p := filepath.Join(t.TempDir(), "bench.jsonl")
	l, err := OpenLog(p, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Write(rec(i, "m")); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	got, err := ReadFiles(p)
	if err != nil || len(got) != 3 || got[2].T != rec(2, "m").T {
		t.Fatalf("%v %v", got, err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatal(st.Mode())
	}
}

func TestLogRotationBounded(t *testing.T) {
	t.Skip("unimplemented: W14 Task 3")
	p := filepath.Join(t.TempDir(), "bench.jsonl")
	l, _ := OpenLog(p, 1000)
	for i := 0; i < 200; i++ {
		l.Write(rec(i, "xxxxxxxxxxxxxxxxxxxx"))
	}
	l.Close()
	a, _ := os.Stat(p)
	b, err := os.Stat(p + ".1")
	if err != nil || a.Size() > 1000 || b.Size() > 1000 {
		t.Fatalf("%v %v", a, b)
	}
	got, _ := ReadFiles(p)
	if len(got) == 0 || got[len(got)-1].T != rec(199, "").T {
		t.Fatal("newest record missing")
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].T.Before(got[j].T) }) {
		t.Fatal("unsorted")
	}
}

func TestLogReopenAppends(t *testing.T) {
	t.Skip("unimplemented: W14 Task 3")
	p := filepath.Join(t.TempDir(), "bench.jsonl")
	l, _ := OpenLog(p, 1<<20)
	l.Write(rec(0, "a"))
	l.Close()
	l, _ = OpenLog(p, 1<<20)
	l.Write(rec(1, "b"))
	l.Close()
	if got, _ := ReadFiles(p); len(got) != 2 {
		t.Fatal(got)
	}
}

func TestReadSkipsTornLine(t *testing.T) {
	t.Skip("unimplemented: W14 Task 3")
	p := filepath.Join(t.TempDir(), "b.jsonl")
	os.WriteFile(p, []byte(`{"t":"2023-11-14T22:13:20Z","kind":"mark","mark":"a"}`+"\n"+`{"t":"2023-11-14T22:1`), 0o600)
	got, err := ReadFiles(p)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	os.WriteFile(p, []byte("garbage\n"+`{"t":"2023-11-14T22:13:20Z","kind":"mark","mark":"a"}`+"\n"), 0o600)
	if _, err := ReadFiles(p); err == nil {
		t.Fatal("garbage in the middle accepted")
	}
}

func TestReadRefusesHugeLine(t *testing.T) {
	t.Skip("unimplemented: W14 Task 3")
	p := filepath.Join(t.TempDir(), "b.jsonl")
	os.WriteFile(p, []byte(strings.Repeat("x", 2<<20)+"\n"), 0o600)
	if _, err := ReadFiles(p); err == nil {
		t.Fatal("2 MiB line accepted")
	}
}

func TestAppendMark(t *testing.T) {
	t.Skip("unimplemented: W14 Task 3")
	p := filepath.Join(t.TempDir(), "marks.jsonl")
	AppendMark(p, "partition_start", time.Unix(1700000000, 0))
	AppendMark(p, "partition_end", time.Unix(1700000060, 0))
	got, _ := ReadFiles(p)
	if len(got) != 2 || got[1].Mark != "partition_end" || got[1].Kind != KindMark {
		t.Fatal(got)
	}
}
