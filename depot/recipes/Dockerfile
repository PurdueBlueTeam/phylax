# Reproducible static build environment for the Phylax tool depot (linux/amd64).
# NOT run in CI. Run in the lab (or any machine with internet) via build.sh.
# Alpine/musl gives fully static binaries with no host loader dependency.
# Pin the base by digest before the event: `docker pull alpine:3.20` then
# replace the tag below with alpine:3.20@sha256:<digest> and commit it.
FROM alpine:3.20
RUN apk add --no-cache build-base linux-headers bash curl xz tar patch perl \
      autoconf automake libtool pkgconf gettext-dev gettext-static m4 bison flex \
      bzip2 coreutils musl-dev openssl-dev openssl-libs-static zlib-dev zlib-static \
      libpcap-dev ncurses-dev ncurses-static readline-dev readline-static \
      libmnl-dev libmnl-static elfutils-dev libcap-dev libcap-static \
      libelf-static bzip2-static xz-dev bison-dev file-dev
COPY versions.env build-tool.sh /recipes/
WORKDIR /work
ENTRYPOINT ["/bin/bash", "/recipes/build-tool.sh"]
