# YTLiteUnlock — usage & iteration guide

`YTLiteUnlock` is the first-party companion tweak that sits on top of the
official (closed) YTLite build and neutralizes its Patreon gate. Its source is
fully auditable — that's the entire point vs. community "cracks".

## Build (via CI, no Mac needed)

Run the **"[Unlocked] Build YTLiteUnlock and bake a YouTube Plus IPA"**
workflow from the repo's Actions tab. Two artifacts come out:

| artifact | use |
| --- | --- |
| `YTLiteUnlock` (.deb) | jailbreak/Sileo install, or the Form-2 cyan bake |
| `YTLiteUnlock-dylib` (.dylib) | LiveContainer *Tweaks* tab import |

## Two ways to use it

### Form 1 — LiveContainer overlay (no repackaging)

1. Build the official YTLite IPA with the existing **Create YouTube Plus app**
   workflow; import it into LiveContainer as usual.
2. Download the `YTLiteUnlock-dylib` artifact.
3. In LC: **Tweaks tab → + → Import Tweak** → pick the `.dylib`.
4. Create a folder under *Tweaks* (e.g. "YT Unlocked"), move the tweak into it,
   then in app settings for the YouTube guest app set **Tweak Folder** to it.

### Form 2 — baked IPA

Run the **[Unlocked]** workflow with either:
- `ipa_url` = direct link to an IPA already containing YTLite (from your fork's
  releases — leave `ipa_url` empty to auto-pick the newest one), or
- `ipa_url` = link to a **raw decrypted YouTube IPA** with
  `ipa_has_ytplus = false` and the appropriate official `ytplus_version`.
  The workflow then injects `ytplus.deb` + `YTLiteUnlock.deb` itself.

## Test loop (Linux host, no jailbreak)

```
sudo apt install libimobiledevice-utils
idevicesyslog | grep YULU
```

- Attach the iPhone over USB while the app runs in LC.
- Everything the tweak does is prefixed `[YULU]`);

```text
[YULU] v1 start (spoof=1) app=com.google.ios.youtube
[YULU] scan (tick 3): 187 classes runtime-wide, 2 interesting, 0 dumped
[YULU] class DVNPatreonContext (super=…) 12 methods
[YULU]   method isActivated args=2 types=B16@0:4 (getter)
[YULU] SPOOF -[DVNPatreonContext isActivated] forced YES
```

## Tuning

- **Disable the spoof but keep instrumentation** — edit the app's
  `NSUserDefaults` (`YTLiteUnlockSpoof = NO`) or rebuild with
  `{ app defaults domain }`.
- **Method dumps** appear just once per class per launch; search for
  `class <Name>` to see the full table, then `SPOOF` lines to see what
  got touched.

## What's hooked (v1 limits)

Only zero-argument truth-like getters (`isActivated`-style) on classes whose
names match the gate vocabulary, inside classes named `DVN*` or `WelcomeVC`.
Call sites with arguments, or features re-validating server side, are NOT
spoofed in v1 — expect the next iteration to add per-feature hooks once the
runtime dump of the previous build is read.

## Local tooling

- `tools/classdump.py` — offline ObjC metadata dumper for the official
  `YTLite.dylib` (patterns: class name → selector list + type encodings).
  Usage: `python3 tools/classdump.py <path-to-deb> [filter…]`
  The runtime self-dump (inside LC) is the authoritative companion for any
  gate asset class that got registered at runtime (offline scan shows they
  do NOT appear in the static class list — see NOTES.md §3.1).
