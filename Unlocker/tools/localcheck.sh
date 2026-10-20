#!/usr/bin/env bash
# Local syntax gate for the Unlocker tweak.
# Preprocesses Logos -> ObjC, then runs clang -fsyntax-only against the
# iPhoneOS 16.5 SDK so compile errors are caught locally in seconds
# instead of failing a GitHub runner minutes later.
#
# Requirements (one-time):
#   ~/.theos-quick/iPhoneOS16.5.sdk            (from theos/sdks, sparse)
#   ~/.theos-quick/theos                       (logos + vendor/include)
#   ~/.theos-quick/local-include/CydiaSubstrate/CydiaSubstrate.h
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"   # <- repo root (YTLite/)
SRC="${1:-$REPO_ROOT/Unlocker/Tweak.x}"
WORK="$(mktemp -d /tmp/gate-le.e.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

THEOS="${THEOS:-$HOME/.theos-quick/theos}"
SDK="${SDK:-$HOME/.theos-quick/iPhoneOS16.5.sdk}"
EXTRA_INC="${EXTRA_INC:-$HOME/.theos-quick/local-include}"

perl "$THEOS/vendor/logos/bin/logos.pl" "$SRC" > "$WORK/Tweak.m"

# shellcheck disable=SC2086
clang -x objective-c -fobjc-arc -fexceptions -std=gnu11 \
  -target arm64-apple-ios13.0 -isysroot "$SDK" \
  -I "$THEOS/vendor/include" \
  -I "$EXTRA_INC" \
  -fsyntax-only "$WORK/Tweak.m"

echo "[gate] $SRC: syntax OK"
