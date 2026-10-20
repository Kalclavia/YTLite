#!/usr/bin/env bash
# Local Linux build of YTLiteUnlock.dylib — bypasses GitHub macOS runners entirely.
# Produces the same artifact class as CI (arm64 iOS dylib, ldid-adhoc-signed,
# strong CydiaSubstrate dep with the LC-proven install name).
#
# Needs (all already present in this workspace):
#   ~/.theos-quick/iPhoneOS16.5.sdk        sparse iOS SDK (tbd stubs)
#   ~/.theos-quick/theos                   logos.pl + vendor/include
#   ~/.theos-quick/local-include           CydiaSubstrate headers
#   system clang 23 (Mach-O emitter) + lld  (ld64.lld emulation) + ldid (fetched)
#
# Gotchas baked in here so you don't rediscover them:
#   - Linux clang will NOT pick a Mach-O linker for *-apple-* targets: invoke
#     ld64.lld MANUALLY (clang driver also fails to forward -arch/-platform_version).
#   - lld dispatches its emulation from argv[0]; symlinking it as "ld" puts it in
#     ELF mode. exec a file literally named ld64.lld.
#   - This lld has NO TAPI support: .tbd stubs -> "unsupported file type".
#     Link against a tiny REAL stub dylib instead; only its install_name is
#     consulted at runtime because LC's bundled CydiaSubstrate carries the
#     same install name and exports the same symbols.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
THEOS="${THEOS:-$HOME/.theos-quick/theos}"
SDK="${SDK:-$HOME/.theos-quick/iPhoneOS16.5.sdk}"
EXP="${EXP:-$HOME/.theos-quick/local-include}"
WORK="$(mktemp -d /tmp/yulu-localbuild.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helper linker wrapper -------------------------------------------------
mkdir -p "$WORK/ldwrap"
printf '#!/bin/bash\nexec "$(dirname "$0")/ld64.lld" "$@"\n' > "$WORK/ldwrap/ld"
chmod +x "$WORK/ldwrap/ld"
ln -sf "$(readlink -f "$(command -v ld64.lld || command -v lld)")" "$WORK/ldwrap/ld64.lld"

# --- preprocess logos ------------------------------------------------------
perl "$THEOS/vendor/logos/bin/logos.pl" "$REPO_ROOT/Unlocker/Tweak.x" > "$WORK/Tweak.m"
clang -x objective-c -fobjc-arc -fexceptions -std=gnu11 \
  -target arm64-apple-ios13.0 -isysroot "$SDK" \
  -I "$THEOS/vendor/include" -I "$EXP" \
  -c "$WORK/Tweak.m" -o "$WORK/Tweak.o"

# --- substrate stub dylib (runtime name only) ------------------------------
mkdir -p "$WORK/stub"
cat > "$WORK/stub/substrate.c" <<'EOF'
void *MSHookFunction(void *symbol, void *replace, void **result) { return symbol; }
void *MSHookMessageEx(void *self, const char *sel, void *imp, void **result) { return imp; }
void *MSHookMessage(void *self, const char *sel, void *imp) { return imp; }
EOF
clang -c -target arm64-apple-ios13.0 -isysroot "$SDK" "$WORK/stub/substrate.c" -o "$WORK/stub/substrate.o"
"$WORK/ldwrap/ld64.lld" -arch arm64 -platform_version ios 13.0 16.5 -dylib \
  -o "$WORK/stub/CydiaSubstrate" \
  -install_name /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate \
  -syslibroot "$SDK" "$WORK/stub/substrate.o" -lSystem

# --- final link ------------------------------------------------------------
"$WORK/ldwrap/ld64.lld" -arch arm64 -platform_version ios 13.0 16.5 -dylib \
  -o "$WORK/YTLiteUnlock.dylib" \
  -install_name /Library/MobileSubstrate/DynamicLibraries/YTLiteUnlock.dylib \
  -syslibroot "$SDK" \
  "$WORK/Tweak.o" "$WORK/stub/CydiaSubstrate" \
  -lobjc -framework Foundation -framework UIKit -framework CoreFoundation \
  -framework Security -lSystem

ldid -S "$WORK/YTLiteUnlock.dylib"
cp "$WORK/YTLiteUnlock.dylib" "$REPO_ROOT/YTLiteUnlock.dylib.localbuild"
echo "[localbuild] done: $REPO_ROOT/YTLiteUnlock.dylib.localbuild"
