// =====================================================================
// YTLiteUnlock — v3.0 "static crack verifier" (observation only)
//
// v3 design change (round 6): the licensing gate of YTLite 6.0.b2 is
// cracked AT BAKE TIME by Unlocker/tools/patch_gate.py — two 4-byte
// patches inside YTLite.dylib __TEXT force the gate's value-return path:
//
//   0xb9be8: bl #0xdfabc           -> mov w0, #1    (validation = true)
//   0xb9ecc: csel w8, w26, w11, ne -> mov w8, w11   (env = clean)
//
// After both patches the gate's dispatcher has exactly one reachable
// terminal state: [[standardUserDefaults] integerForKey:<key>] — every
// YTLite preference is served with its real value. No runtime hooking,
// no process-memory writes -> LiveContainer/AMFI-safe.
//
// THIS DYLIB HOOKS NOTHING AND WRITES NOTHING. MSHookFunction on signed
// __text is fatal under LiveContainer (AMFI CODESIGNING "Invalid Page",
// proved in round 5). Its only job is to verify at runtime that the
// loaded YTLite.dylib carries both patched words, and to say so loudly
// in the boot log — our post-install proof line.
//
// RE details: Unlocker/docs/RE-notes-6.0.b2-gate.md
// =====================================================================

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <string.h>

// patched words (encodings applied by Unlocker/tools/patch_gate.py)
static const uint32_t kPatchAWord = 0x52800020; // mov w0, #1
static const uint32_t kPatchBWord = 0x2A0B03E8; // mov w8, w11

// offsets within YTLite.dylib __TEXT (this build: sha 666ef733...)
static const uint64_t kSiteA = 0xB9BE8; // was bl #0xdfabc
static const uint64_t kSiteB = 0xB9ECC; // was csel w8,w26,w11,ne
static const uint64_t kGateEntry = 0xB98A4; // informational

static void yulu_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[YULU] %@", s);
}

static void verify(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm || !strstr(nm, "YTLite.dylib")) continue;
        const uint8_t *base = (const uint8_t *)_dyld_get_image_header(i);
        if (!base) continue;
        uint32_t a = *(const uint32_t *)(base + kSiteA);
        uint32_t b = *(const uint32_t *)(base + kSiteB);
        BOOL okA = (a == kPatchAWord);
        BOOL okB = (b == kPatchBWord);
        yulu_log(@"YTLite.dylib @ %s (gate entry 0x%llx)",
                 nm, (unsigned long long)kGateEntry);
        yulu_log(@"siteA(0x%llx)=0x%08x %@  siteB(0x%llx)=0x%08x %@",
                 (unsigned long long)kSiteA, a,
                 okA ? @"crack-A OK" : @"crack-A MISSING",
                 (unsigned long long)kSiteB, b,
                 okB ? @"crack-B OK" : @"crack-B MISSING");
        if (okA && okB) {
            yulu_log(@"static crack VERIFIED — preference keys serve real values");
        } else {
            yulu_log(@"WARNING: bake patches absent — licensing gate still active");
        }
        return; // first YTLite.dylib image is the tweaked instance
    }
    yulu_log(@"WARNING: no YTLite.dylib image found — nothing to verify");
}

%ctor {
    @autoreleasepool {
        verify();
    }
}
