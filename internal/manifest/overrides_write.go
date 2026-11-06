package manifest

// AppendOverrides reads dir/overrides.yml (absent: empty), applies fn,
// validates, writes atomically and keeps mode 0600. On any error the file is
// unchanged.
func AppendOverrides(dir string, fn func(*Overrides) error) error {
	panic("unimplemented: W1 Task 11a")
}
