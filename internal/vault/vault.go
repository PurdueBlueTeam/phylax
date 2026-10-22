// Package vault is the controller's encrypted secrets store: one age file,
// passphrase-protected (scrypt), holding versioned entries so a rotation can
// be rolled back. Decrypted values exist only in memory while unlocked.
//
// File format: an age (v1) stream with a single scrypt recipient whose
// plaintext is a JSON document. age authenticates the whole file (header MAC
// and per-chunk AEAD), so any bit flip is reported as ErrCorrupt. Writes are
// atomic (internal/atomicfile).
package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

var (
	ErrLocked          = errors.New("vault: locked")
	ErrWrongPassphrase = errors.New("vault: wrong passphrase")
	ErrCorrupt         = errors.New("vault: file corrupt or tampered")
	ErrNotFound        = errors.New("vault: no such entry or version")
	ErrExists          = errors.New("vault: file already exists")
)

const (
	formatVersion = 1
	// DefaultMaxHistory is how many versions per entry are kept (including current).
	DefaultMaxHistory = 20
	maxFileSize       = 64 << 20
)

// Options tunes a vault. The zero value is the production default.
type Options struct {
	// WorkFactor is the scrypt log2(N) used when encrypting (age default 18,
	// roughly one second). Tests lower it.
	WorkFactor int
	// MaxHistory bounds versions kept per entry (default DefaultMaxHistory).
	MaxHistory int
	// Now overrides the clock (tests).
	Now func() time.Time
}

type version struct {
	ID      string    `json:"id"`
	Value   []byte    `json:"value"`
	Created time.Time `json:"created"`
	Note    string    `json:"note,omitempty"`
}

type entry struct {
	Current  string    `json:"current"`
	Seq      int       `json:"seq"`
	Versions []version `json:"versions"` // oldest first
}

type document struct {
	Format  int               `json:"format"`
	Entries map[string]*entry `json:"entries"`
}

// VersionInfo describes a stored version without its value.
type VersionInfo struct {
	ID      string
	Created time.Time
	Note    string
	Current bool
}

// Vault is safe for concurrent use.
type Vault struct {
	path string
	opt  Options

	mu   sync.Mutex
	pass []byte // held while unlocked, to re-encrypt on write
	doc  *document
}

func (o Options) norm() Options {
	if o.MaxHistory <= 0 {
		o.MaxHistory = DefaultMaxHistory
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Create makes a new empty vault at path and leaves it unlocked. It fails with
// ErrExists if path exists.
func Create(path string, passphrase []byte, opt Options) (*Vault, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("vault: empty passphrase")
	}
	if _, err := os.Stat(path); err == nil {
		return nil, ErrExists
	}
	v := &Vault{path: path, opt: opt.norm(), pass: append([]byte(nil), passphrase...),
		doc: &document{Format: formatVersion, Entries: map[string]*entry{}}}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.saveLocked(); err != nil {
		v.wipeLocked()
		return nil, err
	}
	return v, nil
}

// Open returns a locked vault for an existing file. The file is not read until
// Unlock.
func Open(path string, opt Options) (*Vault, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return &Vault{path: path, opt: opt.norm()}, nil
}

// Unlock decrypts the file with passphrase. A wrong passphrase gives
// ErrWrongPassphrase; a damaged or modified file gives ErrCorrupt.
func (v *Vault) Unlock(passphrase []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	data, err := readBounded(v.path)
	if err != nil {
		return err
	}
	doc, err := decrypt(data, passphrase)
	if err != nil {
		return err
	}
	v.wipeLocked()
	v.pass = append([]byte(nil), passphrase...)
	v.doc = doc
	return nil
}

// Lock wipes decrypted material from memory.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.wipeLocked()
}

// Locked reports whether the vault needs Unlock.
func (v *Vault) Locked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.doc == nil
}

func (v *Vault) wipeLocked() {
	Wipe(v.pass)
	v.pass = nil
	if v.doc != nil {
		for _, e := range v.doc.Entries {
			for i := range e.Versions {
				Wipe(e.Versions[i].Value)
			}
		}
	}
	v.doc = nil
}

// Put stores value as a new current version of name and returns its version
// id ("v1", "v2", ...; never reused). The file is rewritten atomically before
// returning; on a write error the in-memory state is unchanged.
func (v *Vault) Put(name string, value Secret, note string) (string, error) {
	if name == "" {
		return "", errors.New("vault: empty entry name")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.doc == nil {
		return "", ErrLocked
	}
	// Mutate a deep-ish copy of the entry so a failed save rolls back cleanly.
	old := v.doc.Entries[name]
	var e entry
	if old != nil {
		e = *old
		e.Versions = append([]version(nil), old.Versions...)
	}
	e.Seq++
	id := "v" + strconv.Itoa(e.Seq)
	e.Versions = append(e.Versions, version{ID: id, Value: value.Bytes(), Created: v.opt.Now().UTC(), Note: note})
	e.Current = id
	pruned := pruneLocked(&e, v.opt.MaxHistory)
	v.doc.Entries[name] = &e
	if err := v.saveLocked(); err != nil {
		if old != nil {
			v.doc.Entries[name] = old
		} else {
			delete(v.doc.Entries, name)
		}
		Wipe(e.Versions[len(e.Versions)-1].Value)
		return "", err
	}
	for _, p := range pruned {
		Wipe(p)
	}
	return id, nil
}

func pruneLocked(e *entry, max int) (wiped [][]byte) {
	for len(e.Versions) > max {
		// drop the oldest non-current version
		for i, ver := range e.Versions {
			if ver.ID != e.Current {
				wiped = append(wiped, ver.Value)
				e.Versions = append(e.Versions[:i:i], e.Versions[i+1:]...)
				break
			}
		}
	}
	return
}

// Get returns the current value and version id.
func (v *Vault) Get(name string) (Secret, string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.doc == nil {
		return Secret{}, "", ErrLocked
	}
	e := v.doc.Entries[name]
	if e == nil {
		return Secret{}, "", ErrNotFound
	}
	for _, ver := range e.Versions {
		if ver.ID == e.Current {
			return NewSecret(ver.Value), ver.ID, nil
		}
	}
	return Secret{}, "", ErrCorrupt
}

// GetVersion returns a specific historical value.
func (v *Vault) GetVersion(name, id string) (Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.doc == nil {
		return Secret{}, ErrLocked
	}
	e := v.doc.Entries[name]
	if e == nil {
		return Secret{}, ErrNotFound
	}
	for _, ver := range e.Versions {
		if ver.ID == id {
			return NewSecret(ver.Value), nil
		}
	}
	return Secret{}, ErrNotFound
}

// History lists versions oldest first.
func (v *Vault) History(name string) ([]VersionInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.doc == nil {
		return nil, ErrLocked
	}
	e := v.doc.Entries[name]
	if e == nil {
		return nil, ErrNotFound
	}
	out := make([]VersionInfo, len(e.Versions))
	for i, ver := range e.Versions {
		out[i] = VersionInfo{ID: ver.ID, Created: ver.Created, Note: ver.Note, Current: ver.ID == e.Current}
	}
	return out, nil
}

// Rollback makes an earlier version current again. History is kept, so a
// rollback can itself be undone by rolling forward to the newer id.
func (v *Vault) Rollback(name, id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.doc == nil {
		return ErrLocked
	}
	e := v.doc.Entries[name]
	if e == nil {
		return ErrNotFound
	}
	found := false
	for _, ver := range e.Versions {
		found = found || ver.ID == id
	}
	if !found {
		return ErrNotFound
	}
	prev := e.Current
	e.Current = id
	if err := v.saveLocked(); err != nil {
		e.Current = prev
		return err
	}
	return nil
}

// Delete removes an entry and all its history.
func (v *Vault) Delete(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.doc == nil {
		return ErrLocked
	}
	e := v.doc.Entries[name]
	if e == nil {
		return ErrNotFound
	}
	delete(v.doc.Entries, name)
	if err := v.saveLocked(); err != nil {
		v.doc.Entries[name] = e
		return err
	}
	for i := range e.Versions {
		Wipe(e.Versions[i].Value)
	}
	return nil
}

// Names lists entry names, sorted.
func (v *Vault) Names() ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.doc == nil {
		return nil, ErrLocked
	}
	out := make([]string, 0, len(v.doc.Entries))
	for n := range v.doc.Entries {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// ChangePassphrase re-encrypts the vault under a new passphrase.
func (v *Vault) ChangePassphrase(newPass []byte) error {
	if len(newPass) == 0 {
		return errors.New("vault: empty passphrase")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.doc == nil {
		return ErrLocked
	}
	old := v.pass
	v.pass = append([]byte(nil), newPass...)
	if err := v.saveLocked(); err != nil {
		v.pass = old
		return err
	}
	Wipe(old)
	return nil
}

// ExportBackup writes an encrypted copy of the whole vault (with history) to w.
// With recipients it encrypts to those age recipients (for example an X25519
// key held off the controller, so restore does not need the live passphrase);
// with none it encrypts to the current passphrase. The result is a normal vault
// file in the passphrase case, openable with Open/Unlock.
func (v *Vault) ExportBackup(w io.Writer, recipients ...age.Recipient) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.doc == nil {
		return ErrLocked
	}
	if len(recipients) == 0 {
		r, err := v.recipientLocked(v.pass)
		if err != nil {
			return err
		}
		recipients = []age.Recipient{r}
	}
	return encryptDoc(w, v.doc, recipients)
}

// RestoreBackup decrypts a backup produced by ExportBackup with an age identity
// (X25519 case) and writes a new vault at path under passphrase.
func RestoreBackup(path string, backup io.Reader, identity age.Identity, passphrase []byte, opt Options) (*Vault, error) {
	data, err := io.ReadAll(io.LimitReader(backup, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	doc, err := decryptWith(data, identity)
	if err != nil {
		return nil, err
	}
	if len(passphrase) == 0 {
		return nil, errors.New("vault: empty passphrase")
	}
	if _, err := os.Stat(path); err == nil {
		return nil, ErrExists
	}
	v := &Vault{path: path, opt: opt.norm(), pass: append([]byte(nil), passphrase...), doc: doc}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.saveLocked(); err != nil {
		v.wipeLocked()
		return nil, err
	}
	return v, nil
}

func (v *Vault) recipientLocked(pass []byte) (age.Recipient, error) {
	r, err := age.NewScryptRecipient(string(pass))
	if err != nil {
		return nil, err
	}
	if v.opt.WorkFactor > 0 {
		r.SetWorkFactor(v.opt.WorkFactor)
	}
	return r, nil
}

func (v *Vault) saveLocked() error {
	r, err := v.recipientLocked(v.pass)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := encryptDoc(&buf, v.doc, []age.Recipient{r}); err != nil {
		return err
	}
	return atomicfile.WriteFile(v.path, buf.Bytes(), 0o600)
}

func encryptDoc(w io.Writer, doc *document, rs []age.Recipient) error {
	plain, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	defer Wipe(plain)
	ew, err := age.Encrypt(w, rs...)
	if err != nil {
		return err
	}
	if _, err := ew.Write(plain); err != nil {
		return err
	}
	return ew.Close()
}

func decrypt(data, pass []byte) (*document, error) {
	id, err := age.NewScryptIdentity(string(pass))
	if err != nil {
		return nil, err
	}
	id.SetMaxWorkFactor(22)
	return decryptWith(data, id)
}

func decryptWith(data []byte, id age.Identity) (*document, error) {
	r, err := age.Decrypt(bytes.NewReader(data), id)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return nil, ErrWrongPassphrase
		}
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	plain, err := io.ReadAll(io.LimitReader(r, maxFileSize))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	defer Wipe(plain)
	var doc document
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if doc.Format != formatVersion {
		return nil, fmt.Errorf("vault: unsupported format %d", doc.Format)
	}
	if doc.Entries == nil {
		doc.Entries = map[string]*entry{}
	}
	return &doc, nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%w: file too large", ErrCorrupt)
	}
	return data, nil
}
