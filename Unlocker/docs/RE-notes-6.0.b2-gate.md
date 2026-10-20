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

### Runtime locator fingerprint (v2.0 embeds these — unique image-wide, 1 hit)

16 movz/movk pairs at VMA `0xb95c0` (function entry = fingerprint − 0x20):

```
0x528646d5, 0x72bcf6d5, 0x52879f36, 0x72b4a916,   /* w21 = 0xa20b2dea-family guards */
0x5285bd57, 0x72b44177, 0x529dda78, 0x72b41758,
0x529a3c39, 0x72b19c39, 0x528ea5fa, 0x72ada9fa,
0x5286e81b, 0x72aba39b, 0x528ea51c, 0x72a41b5c,
```

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
