# YTLiteUnlock — current test build

The v3 build applies two checked patches to the official YTLite 6.0.b2
binary before packaging and signing. The companion dylib only logs whether
those patches are present. Importing that dylib alone does not unlock an app.

## Build

Run **[Unlocked] Build YTLiteUnlock and bake a YouTube Plus IPA**:

- Use a stock decrypted YouTube 21.41.5 IPA, or leave `ipa_url` empty to
  use the stored `base-youtube-21.41.5` release.
- Set `ipa_has_ytplus=false`, `ytplus_version=6.0.b2`,
  `ytplus_tag=v6.0-b2`, and `expected_youtube_version=21.41.5`.
- Download the `YouTubePlus-Unlocked` artifact after the workflow succeeds.

The patcher refuses unrecognized binaries. The packaging job installs its own
`dpkg` dependency and verifies both patches in the finished IPA.

## Test in LiveContainer

1. Extract `YouTubePlus_6.0.b2_Unlocked.ipa` from the artifact ZIP.
2. Disable the previous app-specific unlocker tweak folder for this test.
   An old runtime hook can still crash the new app if loaded externally.
3. Import the new IPA through LiveContainer's **Apps** tab. Use a separate
   app entry if you want to preserve the existing installation and its data.
4. Launch it, then test settings, playback, and the features you need.

The previous build was killed with `CODESIGNING / Invalid Page` when its
runtime hook modified a signed code page. The new companion performs no
runtime code writes. Device launch and feature behavior still require testing.

## Logs

Attach the iPhone over USB and run:

```sh
idevicesyslog | rg YULU
```

The expected line is `static crack VERIFIED`. If the app still closes,
retrieve its new `.ips` crash report; successful packaging alone does not
prove a successful device launch.

## Verifying a third-party decrypted base IPA

No decrypted IPA has a remaining Apple code signature (decryption rewrites
`__TEXT`), so *cryptographic* provenance can't be established for **any**
dumper source — ipadump included. What we can and do verify, automatically
in CI (and locally):

```
# local: metadata + inventory + Mach-O load-commands + endpoint sweep
python3 Unlocker/tools/verify_ipa.py path/to/base.ipa \
        --expect-bundle com.google.ios.youtube --expect-version 21.41.5

# strongest local check: consensus across two independent sources
# (e.g. the ipadump file vs the IPA you already run in LiveContainer)
python3 Unlocker/tools/verify_ipa.py --crosscompare new.ipa currently-running.ipa
```

Checks performed:

- `Info.plist` against Apple's App Store registry (bundle id `com.google.ios.youtube`,
  version, MinOS — reported; version mismatch is fatal).
- File-name sweep for tweak/hook/crack artifacts (`substrate`, `libhooker`,
  `frida`, `crack`, `tweak`, …).
- Every embedded binary: valid Mach-O, arch listing, load-command dylib paths
  restricted to System/`@rpath`+own frameworks, LC code-signature state
  reported, suspicious hook-API strings flagged.
- URL extraction from all binaries (and unknown data files): hosts outside
  the official Google/Apple+ads analytics allowlist are flagged individually.
- Cross-compare mode: inventory + per-file SHA-256 + URL-host-set diff,
  ignoring known-volatile entries (`_CodeSignature`, `SC_Info`, provisioning).

In the `[Unlocked]` workflow this runs automatically on `base.ipa`; the
report ships as `verify-report.txt` inside the `YouTubePlus-Unlocked`
artifact, flags appear as job-log warnings, and only fatal problems
(wrong bundle id / version) refuse the bake.

Interpretation guide:

- **PASS** → as good as any dumper source can be proven.
- **Few FLAGs on Google-side noise** → review the report manually (e.g.
  ML/bundled libs can mention odd hosts); judgement call, not auto-fatal.
- **Cross-compare matches on all three levels** → selective tampering is
  very unlikely; trust your existing LC IPA as the second source whenever
  possible.
- **Persistent FLAGs on non-Google hosts with sensory names** ("collector.",
  "beacon", "track", short odd TLDs) → do not use that source.

## Local tooling

- `tools/classdump.py` — offline ObjC metadata dumper for the official
  `YTLite.dylib` (patterns: class name → selector list + type encodings).
  Usage: `python3 tools/classdump.py <path-to-deb> [filter…]`
  The runtime self-dump (inside LC) is the authoritative companion for any
  gate asset class that got registered at runtime (offline scan shows they
  do NOT appear in the static class list — see NOTES.md §3.1).
