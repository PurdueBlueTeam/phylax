#!/bin/bash
# Build one static tool inside the recipe container.
#   docker run --rm -v "$PWD/out:/out" phylax-depot-build <tool>
# Output: /out/<tool> (a single static linux/amd64 ELF). The tarball hash is
# checked against versions.env before anything is unpacked. Not run in CI.
set -euo pipefail
. /recipes/versions.env
tool=${1:?usage: build-tool.sh <tool>}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1700000000}   # reproducible timestamps
export CFLAGS="-Os -static -ffile-prefix-map=/work=. -fdebug-prefix-map=/work=."
export LDFLAGS="-static"
J=$(nproc)

fetch() { # fetch <PREFIX>: download and verify the pinned tarball, unpack into /work/src
  local u=${1}_URL s=${1}_SHA256
  [ -n "${!s}" ] || { echo "refusing: ${s} is empty in versions.env" >&2; exit 2; }
  mkdir -p /work/src && cd /work/src
  f=$(basename "${!u}")
  if [ -f "/srccache/$f" ]; then cp "/srccache/$f" "$f"; else curl -fsSLO "${!u}"; fi   # cache is hash-checked below too
  echo "${!s}  $f" | sha256sum -c -
  tar xf "$f" && cd "$(tar tf "$f" | head -1 | cut -d/ -f1)"
  true
}
strip_out() { strip -s "$1" && install -m0755 "$1" "/out/$2"; }

case "$tool" in
busybox)
  fetch BUSYBOX
  make defconfig
  sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/; s/CONFIG_TC=y/# CONFIG_TC is not set/' .config
  make -j"$J" busybox
  strip_out busybox busybox
  ./busybox --list > /out/busybox.applets ;;     # paste into tools.json "provides"
toybox)
  fetch TOYBOX
  make defconfig
  CFLAGS="$CFLAGS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0" LDFLAGS=-static make -j"$J" toybox   # alpine fortify-headers breaks toybox strncat
  strip_out toybox toybox
  ./toybox > /out/toybox.applets ;;
coreutils)
  fetch COREUTILS
  ./configure --enable-single-binary=symlinks --disable-nls FORCE_UNSAFE_CONFIGURE=1
  make -j"$J"
  strip_out src/coreutils coreutils ;;   # multi-call; applets via `coreutils --help`
procps)
  fetch PROCPS
  ./configure --disable-shared --enable-static --disable-pidof --disable-nls --without-systemd
  make -j"$J" LDFLAGS=-all-static
  strip_out src/ps/pscommand ps
  strip_out src/top/top top ;;
iproute2)
  fetch IPROUTE2
  ./configure
  sed -i 's/^LDLIBS += *-lelf/LDLIBS += -lelf -lz -lzstd/' config.mk   # static libelf needs its deps
  make -j"$J" LDFLAGS=-static SUBDIRS="lib ip misc"
  strip_out ip/ip ip
  strip_out misc/ss ss ;;
lsof)
  fetch LSOF
  ./configure --disable-shared LDFLAGS=-static
  make -j"$J" LDFLAGS=-all-static lsof
  strip_out lsof lsof ;;
net-tools)
  fetch NETTOOLS
  yes "" | make config >/dev/null || true
  make -j"$J" LDFLAGS="-static -L$PWD/lib" netstat
  strip_out netstat netstat ;;
tcpdump)
  fetch LIBPCAP
  ./configure --disable-shared --without-libnl --disable-dbus --disable-rdma --disable-bluetooth
  make -j"$J"
  make install
  fetch TCPDUMP
  ./configure
  make -j"$J" LDFLAGS=-static
  strip_out tcpdump tcpdump ;;
strace)
  fetch STRACE
  ./configure --enable-mpers=no LDFLAGS=-static
  make -j"$J"
  strip_out src/strace strace ;;
curl)
  fetch CURL
  ./configure --disable-shared --enable-static --with-openssl --without-libpsl --disable-ldap --disable-docs \
    --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt
  make -j"$J" LDFLAGS=-all-static
  strip_out src/curl curl ;;
socat)
  fetch SOCAT
  ./configure --disable-readline LDFLAGS=-static
  make -j"$J"
  strip_out socat socat ;;
openssh)
  fetch OPENSSH
  ./configure --without-pam --with-ldflags=-static
  make -j"$J" ssh scp ssh-keygen
  strip_out ssh ssh
  strip_out scp scp
  strip_out ssh-keygen ssh-keygen ;;
file)
  fetch FILE
  ./configure --disable-shared --enable-static
  make -j"$J" LDFLAGS=-all-static
  strip_out src/file file
  install -m0644 magic/magic.mgc /out/magic.mgc ;;   # run with -m <depot>/magic.mgc
findutils)
  fetch FINDUTILS
  ./configure --disable-nls LDFLAGS=-static
  make -j"$J"
  strip_out find/find find
  strip_out xargs/xargs xargs ;;
grep)
  fetch GREP
  ./configure --disable-nls LDFLAGS=-static
  make -j"$J"
  strip_out src/grep grep ;;
tar)
  fetch TAR
  ./configure --disable-nls LDFLAGS=-static FORCE_UNSAFE_CONFIGURE=1
  make -j"$J"
  strip_out src/tar tar ;;
gzip)
  fetch GZIP
  ./configure LDFLAGS=-static
  make -j"$J"
  strip_out gzip gzip ;;
xz)
  fetch XZ
  ./configure --disable-shared --disable-nls LDFLAGS=-static
  make -j"$J" LDFLAGS=-all-static
  strip_out src/xz/xz xz ;;
nmap)   # optional: large, needs the data files shipped alongside (nmap-services etc.)
  fetch NMAP
  ./configure --without-zenmap --without-ndiff --without-nping --without-ncat LDFLAGS=-static
  make -j"$J"
  strip_out nmap nmap
  # data files travel as ONE deterministic tar entry (depot tools are single files);
  # unpack with the depot tar into a private dir and run `nmap --datadir <dir>`.
  mkdir -p /tmp/nmap-data
  cp -r nmap-services nmap-protocols nmap-rpc nmap-service-probes nmap-os-db nmap-mac-prefixes nse_main.lua scripts nselib /tmp/nmap-data/
  tar -C /tmp/nmap-data --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner --format=posix \
      --pax-option=delete=atime,delete=ctime -cf /out/nmap-data.tar . ;;
*) echo "unknown tool $tool" >&2; exit 2 ;;
esac
echo "built $tool"
