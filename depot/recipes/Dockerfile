# Reproducible static build environment for the Phylax tool depot (linux/amd64).
# NOT run in CI. Run in the lab (or any machine with internet) via build.sh.
# Alpine/musl gives fully static binaries with no host loader dependency.
# Base is pinned by digest (alpine:3.20 as of 2026-10-22); bump deliberately.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache build-base linux-headers bash curl xz tar patch perl \
      autoconf automake libtool pkgconf gettext-dev gettext-static m4 bison flex \
      bzip2 coreutils musl-dev openssl-dev openssl-libs-static zlib-dev zlib-static \
      ncurses-dev ncurses-static readline-dev readline-static \
      libmnl-dev libmnl-static elfutils-dev libcap-dev libcap-static \
      libelf-static bzip2-static xz-dev xz-static zstd-dev zstd-static git
COPY versions.env build-tool.sh /recipes/
WORKDIR /work
ENTRYPOINT ["/bin/bash", "/recipes/build-tool.sh"]
