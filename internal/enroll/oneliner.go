package enroll

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// OS names used by the generators and the handler routes.
const (
	OSLinux   = "linux"
	OSWindows = "windows"
)

// OneLiner returns the line to type on a console. ctl is host:port as the host
// sees the controller.
func (e *Enroller) OneLiner(osName, ctl, token string) (string, error) {
	if strings.TrimSpace(ctl) == "" {
		return "", errors.New("enroll: one-liner needs a controller address")
	}
	switch osName {
	case OSLinux:
		if _, _, err := e.release(osName); err != nil {
			return "", err
		}
		return fmt.Sprintf("curl -sk --pinnedpubkey %s https://%s/l/%s|sh",
			e.opt.Identity.Pin.Curl(), ctl, token), nil
	case OSWindows:
		if _, _, err := e.release(osName); err != nil {
			return "", err
		}
		return fmt.Sprintf("powershell -c \"[Net.ServicePointManager]::SecurityProtocol=3072;"+
			"[Net.ServicePointManager]::ServerCertificateValidationCallback={param($s,$c)$c.GetCertHashString() -eq '%s'};"+
			"iex(iwr https://%s/w/%s -UseBasicParsing)\"", e.thumbprint(), ctl, token), nil
	default:
		return "", fmt.Errorf("enroll: unknown OS %q", osName)
	}
}

// thumbprint is the uppercase SHA-1 of the controller certificate, the hash
// .NET Framework 4.x exposes without extra code (design: Windows pin).
func (e *Enroller) thumbprint() string {
	sum := sha1.Sum(e.opt.Identity.Cert.Certificate[0])
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// linuxScript fetches, verifies and installs the Linux agent with the same pin
// as the typed line.
func (e *Enroller) linuxScript(ctl, token, sha, dir string) (string, error) {
	return renderScript("linux", linuxTemplate, map[string]string{
		"Pin":       e.opt.Identity.Pin.Curl(),
		"Dir":       dir,
		"BinaryURL": "https://" + ctl + "/b/" + token + "/linux",
		"BootURL":   "https://" + ctl + "/b/" + token + "/boot",
		"SHA256":    sha,
	})
}

// windowsScript is the script the typed Windows line downloads and runs.
func (e *Enroller) windowsScript(ctl, token, sha, dir string) (string, error) {
	return renderScript("windows", windowsTemplate, map[string]string{
		"Thumb":     e.thumbprint(),
		"Dir":       dir,
		"BinaryURL": "https://" + ctl + "/b/" + token + "/windows",
		"BootURL":   "https://" + ctl + "/b/" + token + "/boot",
		"SHA256":    sha,
	})
}

const linuxTemplate = `set -e
d="${PHYLAX_DIR:-${INSTALL_DIR:-/opt/{{.Dir}}}}"
mkdir -p "$d"
curl -sk --pinnedpubkey {{.Pin}} -o "$d/phylax" {{.BinaryURL}}
printf '%s  %s\n' '{{.SHA256}}' "$d/phylax" | sha256sum -c -
chmod 700 "$d/phylax"
curl -sk --pinnedpubkey {{.Pin}} -o "$d/boot.json" {{.BootURL}}
"$d/phylax" agent install --bootstrap "$d/boot.json"
rm -f "$d/boot.json"
`

const windowsTemplate = `$ErrorActionPreference='Stop';` +
	`[Net.ServicePointManager]::SecurityProtocol=3072;` +
	`[Net.ServicePointManager]::ServerCertificateValidationCallback={param($s,$c)$c.GetCertHashString() -eq '{{.Thumb}}'};` +
	`$d=if($env:PHYLAX_DIR){$env:PHYLAX_DIR}else{Join-Path $env:ProgramFiles '{{.Dir}}'};` +
	`New-Item -ItemType Directory -Force -Path $d|Out-Null;` +
	`Invoke-WebRequest '{{.BinaryURL}}' -OutFile (Join-Path $d 'phylax.exe') -UseBasicParsing;` +
	`if((Get-FileHash (Join-Path $d 'phylax.exe') -Algorithm SHA256).Hash -ne '{{.SHA256}}'){throw 'phylax: binary hash mismatch'};` +
	`Invoke-WebRequest '{{.BootURL}}' -OutFile (Join-Path $d 'boot.json') -UseBasicParsing;` +
	`& (Join-Path $d 'phylax.exe') agent install --bootstrap (Join-Path $d 'boot.json');` +
	`Remove-Item (Join-Path $d 'boot.json')`
