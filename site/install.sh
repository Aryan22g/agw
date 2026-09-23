#!/bin/sh
# Install agw, agw-verify and ags from a GitHub release.
#
#   curl -fsSL https://aryan22g.github.io/agw/install.sh | sh
#
# Read it first; it is short. It downloads one archive and SHA256SUMS for
# your OS and architecture, refuses to continue if the checksum does not
# match, and copies three binaries into a directory on your PATH. It never runs
# anything it downloaded, and it uses sudo only if you ask for a system
# directory that needs it.
#
# Environment:
#   AGW_VERSION        a release tag, e.g. v0.1.0 (default: the latest release)
#   AGW_INSTALL_DIR    where to put the binaries (default: /usr/local/bin if
#                      writable, else ~/.local/bin)
#   AGW_DOWNLOAD_BASE  release download base URL (for mirrors and air gaps)
set -eu

REPO="Aryan22g/agw"
BASE="${AGW_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download}"
BINS="agw agw-verify ags"

say()  { printf '%s\n' "$*"; }
fail() { printf 'agw install: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "needs $1"; }

need curl
need tar
need uname

os=$(uname -s)
case "$os" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported OS $os; download a release archive by hand from https://github.com/$REPO/releases" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) fail "unsupported architecture $arch" ;;
esac

version="${AGW_VERSION:-}"
if [ -z "$version" ]; then
  # The latest-release page redirects to .../tag/<version>. Following the
  # redirect needs no API token and has no rate limit.
  url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") \
    || fail "could not find the latest release"
  version=${url##*/}
  case "$version" in v*) ;; *) fail "no release has been published yet" ;; esac
fi

name="agw_${version}_${os}_${arch}"
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t agw)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "agw $version for $os/$arch"
curl -fsSL -o "$tmp/$name.tar.gz" "$BASE/$version/$name.tar.gz" || fail "download failed: $BASE/$version/$name.tar.gz"
curl -fsSL -o "$tmp/SHA256SUMS" "$BASE/$version/SHA256SUMS" || fail "download failed: SHA256SUMS"

want=$(awk -v f="$name.tar.gz" '$2 == f || $2 == "*"f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$want" ] || fail "SHA256SUMS has no entry for $name.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$name.tar.gz" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  got=$(shasum -a 256 "$tmp/$name.tar.gz" | awk '{print $1}')
else
  fail "needs sha256sum or shasum to check the download"
fi
[ "$got" = "$want" ] || fail "checksum mismatch for $name.tar.gz (expected $want, got $got); nothing was installed"
say "checksum ok"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"

dir="${AGW_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir" 2>/dev/null || true
sudo=""
if [ ! -w "$dir" ]; then
  command -v sudo >/dev/null 2>&1 || fail "$dir is not writable; set AGW_INSTALL_DIR"
  sudo=sudo
  say "$dir needs sudo"
fi
for b in $BINS; do
  $sudo install -m 0755 "$tmp/$name/$b" "$dir/$b"
done
say "installed $BINS into $dir"

case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "" ; say "add it to your PATH:  export PATH=\"$dir:\$PATH\"" ;;
esac

say ""
say "The checksum proves the download is intact. To prove where it was built:"
say "  gh attestation verify $name.tar.gz --repo $REPO"
say ""
say "Next:"
say "  agw init"
