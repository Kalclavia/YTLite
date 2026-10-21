# Gate RE notes — YTLite 6.0.b2 (unlock project)

Static reverse-engineering state backing Unlocker v1.3/v2.0. All addresses are
VMAs inside `YTLite.dylib` (official 6.0.b2 tweak, 38 MB arm64). Offline tooling
lives in `/tmp/opencode` on the analysis machine (scratch — mirror anything
permanent into this file).

## 1. Obfuscation architecture

Every function is compiled as a state machine:

- each basic block ends in a computed indirect jump (`br xN`) selected by an
  anti-tamper flag (`ldar w9,[0x228e6b4]`-style; flag==0 / flag!=0 selects one
  of 2 table entries; target = `TAB[i] + sext(-(DAT^magic))`);
- second-level stubs read table pointers stashed by earlier blocks
  (`stp x11,x10,[sp,#0x30]` → `ldr x9,[sp,#0x30]`), so any resolver must keep
  function-global state;
- stub shapes: 2-entry cset-indexed; **data-driven multi-entry**
  (`ldr x8,[x8,wNR,uxtw #3]` indexed by a return value, table base e.g.
  `0x21c2ff8`, up to ~64 entries).

`0xb99a4` is NOT a stub start (resolver failure there is expected — it is a
mid-body block; the enclosing huge function truly starts at `0xb95a0`).

## 2. The gate chokepoint: `0xb95a0`

One fat licensing-manager function:

- prologue `sub sp,#0x1f0; stp x28,x27,…; stp x29,x30,[sp,#0x1e0]; add x29,sp,#0x1e0`
  → u32 `0xd107c3ff, 0xa9196ffc, 0xa91a67fa, 0xa91b5ff8` (then `0xa91b5ff8,
  0xa91c57f6, 0xa91d4ff4, 0xa91e7bfd, 0x910783fd`);
- entry loads 8 guard magics (movz/movk pairs) into w21–w28:
  `0xe7b63236, 0xa5483cf9, 0xa20b2dea, 0xa0baeed3, 0x8ce1d1e1, 0x6d4f752f,
  0x5d1c3470(?), 0x20da7528`;
- ends comparing a decoded value against `w21` (`cset w9, lt`) after writing
  accept/reject constants (w22/w24) through an out-pointer;
- **75 `bl 0xb95a0` call sites**, every one inside a thin `stp/bl/ldp/ret`
  veneer; the veneer onion continues upward (0x12fbc ← 0x12fd0, 0x13000 ←
  0x13014; call-site clusters at 0x31894–0x31984, 0x39668, 0x45ae4–0x481b4
  (~30), 0x64eec–0x673f0, 0x8acf0–0x8cdbc, 0x165e90, 0x1abb14–0x1b15bc,
  0x26d9e0–0x2729d8 — all plain-C feature code, un-ObjC). Full list:
  `/tmp/opencode/callers_b95a0.txt`.

### Runtime locator fingerprint (v2.2 embeds these — unique in the SHIPPED image)

**Build-variant lesson (round 4, 2026-10-20):** the .deb ships TWO branches —
rootless (`var/jb/…/YTLite.dylib`, gate at 0xb95a0, 8 movz/movk pairs, the
build the offline RE covered) and rootful (injected by cyan into the IPA's
`Frameworks/`, gate at 0xb98a4, 4 pairs at entry + 3 more later; later
functions pair up 1:1 with rootless in order but shifted several hundred bytes
and with per-build-randomized magics). The device loads the ROOTFUL build, so
the shipped fingerprint must be extracted from it. The v2.0/v2.1 n-nullable
digs used the rootless constants and correctly reported "no fingerprint match"
— the scan itself was right, the constants were from the wrong branch.

Rootful (shipped) gate fingerprint — first 8 words at fn entry (fn = fp − 0x20;
exactly 1 occurrence in the entire 38 MB file offline-verified):

```
0x52813955, 0x72b7fa15, 0x528e7319, 0x72aae4d9,
0x5293047a, 0x72a780da, 0x5291fa9b, 0x72a4679b,
```

Rootless (analysis) gate fingerprint, for reference:

```
0x528646d5, 0x72bcf6d5, 0x52879f36, 0x72b4a916,
0x5285bd57, 0x72b44177, 0x529dda78, 0x72b41758,
0x529a3c39, 0x72b19c39, 0x528ea5fa, 0x72ada9fa,
0x5286e81b, 0x72aba39b, 0x528ea51c, 0x72a41b5c,
```

Rootless gate VMA 0xb95a0 → rootful gate at 0xb98a4 (same order-relation
holds for the other 22 shared-prologue functions in both builds).

## 3. Strings / prefs

- `0x21c38c0` decrypts to `Access.AccountRequired` inside `0xb7bc0`; keys are a
  per-byte XOR chain readable from disasm (`0x21c38a0→0x21c38c0`); localized via
  `-[NSString(YTL) ytl_localized]` (selref `0x2190958`, wrapper `0xe0354`).
- Gate state vocabulary: `Access.AccountRequired/LogIn/SignInAgain/Status/Active`,
  `dontRemindAccess`, `Welcome.*`.
- Prefs domain: `com.dvntm.ytlite` (CFPrefs) AND plain standard NSUserDefaults
  (round-3 log caught `dontRemindAccess` read = null/0 AND a later write val=0).
- jwt/ticket/accessExpiry/deviceId never appeared in NSUD reads → may live in
  Keychain or only post-login. v2.0 probes Keychain at t15.

## 4. Runtime-visible gate surface (v1.3 round-3 confirmed)

All YTLite classes register at tick 1. Gate-relevant:

- `YTPDownloadsVC` (124 m): `setupLockView` imp 0x343024, `unlockTapped`
  0x344ae0, `isPrivateLocked` 0x34485c, `lockPrivate` 0x344f08,
  `applyLockState` 0x347788, `isPrivateContext` 0x3447bc — lock UI construction
  is pure view-building, no gate decision inside.
- `YTPSettingsBuilder` (31 m): `patreonSection:`, `patreonStatusCell`,
  `patreonButtonCellWithType:model:`.
- `DVNPatreonContext` (hidden, runtime-registered): ASWebAuthenticationSession
  delegate, `presentationAnchorForWebAuthenticationSession:` @ 0xB9F5C.
- `YTLUserDefaults` (class methods `boolForKey:` / `integerForKey:` /
  `setBool:forKey:` / `setInteger:forKey:` — NSUD wrapper).
- `DVNMemoryStore` (13 m), `DVNAlertController`, `DVNSheet*` (alert/UI).
- Exports trie: only `_ytpPlaybackFixAvailable` (0x8df08), `_replaceInfoDict`
  (0x8d68c), `_innertubeName` interesting; veneers/thunks unexported.

## 5. Offline toolchain (scratch scripts, all work end-to-end)

- `resolve_jump.py` — stub resolver, 11/12 seed stubs validated (slot-bug
  fixed); exports `LINE, secmap, bases, b, fixmap`.
- `flatten.py` — CFG flattener following stub chains BFS w/ function-global
  FnState; handles stp/ldp/stur/str/ldur/ldr, compresses XOR-decrypt chains.
- `stub_catalog.py` → `stub_catalog.json` — 3048/12349 computed jumps resolved.
- `importnames.py` → `got_binds.json` — all dyld chained fixups decoded
  (1679 binds / 60478 rebases / 0 failures; 1438 named imports).
- Ghidra 12 = Java only; OSGi cache purge path
  `~/.config/ghidra/ghidra_12.1.2_DEV/osgi/` (compiled-bundles + felixcache)
  if scripts silently recompile-fail; decomp bodies are chained-stub state
  machines Ghidra cannot follow — flattener output is the useful artifact.
- Non-obfuscated veneer table at `0x12eec–0x13080` (thin passthrough thunks).

## 6. What round 4 (v2.0) decides for round 5 (v3)

v2.0 transparently hooks `0xb95a0` at runtime and logs args+returns of every
gate call during real feature use (downloads screen, background play, etc.).
Round 5 = replace the return with the "granted" constant (or suppress the
reject branch) once the convention is seen; gate-class observe hooks + NSUD
write sniff + prefs/Keychain dumps fill in state layout in the same round.
Known risk: `MSHookFunction` is a weak import — if LC's Substrate shim does
not export it, the gate hook self-skips and recon still proceeds via the
class hooks; round 5 would then hook the 2 thin veneers with
MSHookMessageEx-style inline patch fallback or use fishhook.

## 7. Round-4 runtime recap (device log /tmp/yulu-boot4.log, 2026-10-20)

- Fingerprint scan ran on the named YTLite image (23 MB __text) at ticks
  1-13, `MSHookFunction present=1`, zero matches → rootless-vs-rootful
  constants issue above (fixed in v2.2).
- 18 observe hooks installed each boot; `-[YTPSettingsBuilder patreon*]`
  encodings captured: `patreonSection: @24@0:8@16`, `patreonStatusCell
  @16@0:8`, `patreonButtonCellWithType:model: @32@0:8@16@24` — all return
  `DVNCell`/`DVNSection` (pure UI builders, gate decision elsewhere).
- Keychain: Google-SSO tokens only (`com.google.sso.optional.1.accessToken`
  acc=<YouTube-account-63-digit-id>, len 310) — YTLite gate login state is
  NOT in Keychain under dvn/ytl names (probe at t15 both boots).
- App-domain NSUD write-vocabulary this round = YouTube's own keys; no
  dvntm/access/jwt writes appeared on disk either round yet — gate state
  likely in-memory or server-side cookie only.
- `DVNPatreonContext` never registered as an objectifiable class this boot
  (its presentationAnchor hook absent) — it appears only during the login
  web-flow, so hooking it requires triggering the login screen before
  tick-class-discovery completes (or hooking by lazily rescanning — v2.1's
  5-min scan loop already covers this, and did not fire this round: the
  login page was opened through LC's embedded auth, class resolved inside
  a private framework context? round 5 tip: open the login sheet EARLY).

## 8. Round 5 confirmed: runtime text hooks are fatal under LiveContainer

v2.2 baked IPA imported as LC app → SIGKILL on launch, zero YULU log lines:
`MSHookFunction` patched signed `YTLite.dylib` `__text` → kernel terminates
with `CODESIGNING — "Invalid Page"`. Crash report
`LiveContainer-2026-10-20-222148.ips`: frame #0 = YTLite.dylib + the hooked
gate entry. ANY runtime write into method bodies of a signed image dies under
LC. ObjC-method-swizzle level hooks stay LC-safe; function-level do not.
→ v3 goes static: patch the dylib at bake time, re-sign, ship. No hooks.

## 9. Round 6: gate semantics fully solved (rootful build, static)

### What the gate is

Rootful gate = `0xb98a4` (fingerprint above). One fat state-machine function.
Not a boolean check: it is **YTLite's preference reader**. Roughly 75 veneer
call sites pass a preference-key C string in x0; the gate returns the boolean/
integer value for that key. Licensed+crypted: real value. Anything else: **0**
(unchecked → every YTLite feature toggle reads "off"). This explains rounds
1–5 exactly: settings changed nothing while locked.

### Dispatcher mechanics (delivered by flatten.py + symbolic walk)

- Prologue stashes 14 two-entry branch tables (`0x21c9e98…0x21c9fe8`, step
  0x18) into x29/sp slots; every basic block ends in `br xN` selecting
  `TAB[flag]` where `flag = cset(w) from cmp cell,<const>`.
- The "cell" is the internal u32 at `[x29,#-0x84]` (address in `[x29,#-0x90]`):
  blocks write an opcode constant into it (`str wN,[x8]`) and re-dispatch; the
  cmp-chain decodes the opcode (signed lt / eq against the movz constants).
- Constants (w-reg → value): w21=0xBFD009CA w25=0x57267398 w26=0x3C069823
  w27=0x233C8FD4 w24=0x0D1AD0E4 w13=0x6D769CD5 w12=0xB03DCD41 w11=0xDC0EA9EF
  w14=0x8D7E434F w19=0x2E12603C w20=0x0FD1C358 mid-body magic w9=0x8C3CC50A.
  Entry-stub DAT @0x21c9ea8 = 0x2e14f9ec (identity anchor).
- Calls (all real, chained-fixup named): `bl 0xdfabc` → unknown validation
  bool f (cached `[x29,#-0x61]`); `bl 0xdfae0` +
  clsref@0x21979d8/selector "standardUserDefaults" → NSUD (cached
  `[x29,#-0x70]`); `bl 0xdfb00` → objc_msgSend-ish `integerForKey:`
  (selref 0x21915d8 = "integerForKey:", x2 = original x0 = caller's key),
  result cached `[x29,#-0x78]`.
- Tamper byte: global at `0x228e0200`, cached `[x29,#-0x62]` inside the gate.

### Exit paths (symbolic execution of the full dispatcher — 33 states, 3 terminals)

| f (0xdfabc bool) | g (0x228e0200) | result returned to all 75 callers |
|---|---|---|
| 0 | any | ZERO — feature off |
| 1 | 1   | ZERO — "environment tampered" |
| 1 | 0   | **INT — real `integerForKey:<key>` value** (NSUD fetched, key passed) |

f=0 path taken when `0xdfabc` says not-valid; g read via the csel at 0xb9ecc
(`csel w8,w26,w11,ne`: ne → g!=0 → w26=reject; g==0 → w11=accept-op). The
value path then flows: NSUD fetch (`0xb9ccc`) → integerForKey (`0xb9e1c`) →
result forwarded `[-0x78]→[-0x80]` (`0xb9acc`) → epilogue (returns it).

### The crack (bake-time, 8 bytes)

```
0xb9be8: 0x940097b5  bl #0xdfabc            ->  0x52800020  mov w0, #1
0xb9ecc: 0x1a8b1348  csel w8, w26, w11, ne  ->  0x2a0b03e8  mov w8, w11
```

Patch 1 forces f=1 (skips the unknown 0xdfabc check entirely). Patch 2
forces the accept-op write regardless of the tamper byte. Symbolic run of
the patched dispatcher (gate_patch_check.py, patch sites emulated):
**exactly one terminal — the integerForKey value path**, and the tamper
byte's actual value becomes irrelevant. Prologue/veneers/consumer ABI
(no changes; the remaining calls `dfae0/dfb00/173010-...` are untouched and
real).

Ships via `Unlocker/tools/patch_gate.py` run inside the bake:
workflow extracts ytplus.deb (`dpkg-deb -R`), patches the single
`Library/MobileSubstrate/DynamicLibraries/YTLite.dylib`, repacks
(`dpkg-deb -b`) → cyan injects as before → final IPA re-signed by cyan.
The deb dylib and the cyan-baked dylib differ ONLY in load commands
(CydiaSubstrate install-path rewrite) — __TEXT identical, so patch offsets
hold on both; a post-bake `--verify` step re-asserts the crack in the
finished artifact. Re-run requirement on any future YTLite update: offsets
+ anchor 0x21c9ea8 == 0x2e14f9ec must be re-derived (patcher refuses loudly
otherwise).
