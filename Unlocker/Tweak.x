#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <substrate.h>
#import <os/log.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach-o/loader.h>
#import <Security/Security.h>

// =====================================================================
// YTLiteUnlock — v2.1 "recon + crack trial"
//
// Static RE established (offline tooling):
//   - YTLite 6.0.b2 compiles every function as a state machine; every
//     basic block ends in a computed jump through a 2-entry branch table
//     keyed on an anti-tamper flag (3048 stubs resolved offline).
//   - The licensing gate funnels through ONE fat C function at VMA
//     0xb95a0 ("gate"): 75 `bl` call sites, every one inside a thin
//     stp/ldp/ret veneer under feature code (downloads, shorts, player,
//     sponsorblock, download menu...).
//   - Its prologue loads 8 guard immediates (w21..w28); the 16-instruction
//     block at VMA 0xb95c0 is UNIQUE in the whole 38 MB image — perfect
//     runtime offset locator.
//   - Gate strings (Access.AccountRequired / dontRemindAccess / ...) are
//     decrypted at runtime by inline per-byte XOR chains.
//   - v1.3 runtime log confirmed every YTLite class registers live:
//     YTPDownloadsVC (124 m), YTPSettingsBuilder (31 m),
//     YTLUserDefaults, DVNAlert*/DVNSheet*/Toast*, ...
//   - dontRemindAccess was read AND written through plain NSUserDefaults
//     (standard domain): gate state lives there (or Keychain).
//
// v2 behaviour (observe-by-default; spoofer opt-in):
//   1. Fingerprint-locate the gate in the loaded YTLite image and, if
//      MSHookFunction is available, wrap it TRANSPARENTLY (log args +
//      return, pass through). Round 5 replaces the return.
//   2. Type-encoded observe hooks (call-through + log) on gate classes:
//        -[YTPDownloadsVC setupLockView / unlockTapped / lockPrivate /
//            applyLockState / isPrivateLocked / isPrivateContext]
//        -[YTPSettingsBuilder patreonSection: / patreonStatusCell /
//            patreonButtonCellWithType:model:]
//        -[DVNPatreonContext presentationAnchorForWebAuthenticationSession:]
//        +[YTLUserDefaults boolForKey: / integerForKey: /
//            setBool:forKey: / setInteger:forKey:]
//   3. NSUserDefaults read AND write sniffers (writes reveal gate keys
//      the moment the UI persists them).
//   4. CFPrefs com.dvntm.ytlite dump + app-domain gate-vocabulary keys
//      + YTLUserDefaults wrapped prefs dump.
//   5. Keychain probe for dvn/ytl items (deviceId/jwt may live there).
//   6. v1 truth-getter spoofer retained behind YTLiteUnlockSpoof=YES
//      (default OFF for clean observation).
//
// All output prefixed [YULU]: `idevicesyslog | grep YULU`
// =====================================================================

static const uint32_t kGateFP[16] = {
    0x528646d5, 0x72bcf6d5, 0x52879f36, 0x72b4a916,
    0x5285bd57, 0x72b44177, 0x529dda78, 0x72b41758,
    0x529a3c39, 0x72b19c39, 0x528ea5fa, 0x72ada9fa,
    0x5286e81b, 0x72aba39b, 0x528ea51c, 0x72a41b5c,
};
static const uint32_t kGatePrologue[4] = { 0xd107c3ff, 0xa9196ffc, 0xa91a67fa, 0xa91b5ff8 };

// MSHook* live in CydiaSubstrate; LiveContainer maps its ellekit-based
// shim at /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate —
// it exports BOTH MSHookMessageEx and MSHookFunction (verified in LC's
// Resources/Frameworks binary). The dylib links -lsubstrate (vendored
// libsubstrate.tbd stub, install name matches LC's shim exactly).

static NSString * const kSpooferKey = @"YTLiteUnlockSpoof";

#define YLOG(...) do { \
    NSString *_m = [NSString stringWithFormat:__VA_ARGS__]; \
    os_log(OS_LOG_DEFAULT, "[YULU] %{public}@", _m); \
} while (0)

static BOOL spoofEnabled(void) {
    id v = [[NSUserDefaults standardUserDefaults] objectForKey:kSpooferKey];
    if (v == nil) return NO;      // v2: observe by default
    return [v boolValue];
}

static NSString *clampDesc(id v) {
    if (!v) return @"(nil)";
    if ([v isKindOfClass:[NSData class]]) {
        NSData *dd = (NSData *)v;
        NSMutableString *hex = [NSMutableString stringWithFormat:@"<data len=%lu ", (unsigned long)dd.length];
        const unsigned char *b = dd.bytes;
        NSUInteger n = MIN(dd.length, (NSUInteger)12);
        for (NSUInteger i = 0; i < n; i++) [hex appendFormat:@"%02x", b[i]];
        [hex appendString:@">"];
        return hex;
    }
    NSString *d = nil;
    if ([v isKindOfClass:[NSString class]]) d = v;
    else if ([v respondsToSelector:@selector(description)]) {
        @try { d = [v description]; } @catch (__unused id e) { return @"(desc-fail)"; }
    }
    if (d.length > 120) d = [[d substringToIndex:120] stringByAppendingString:@"…"];
    return d ?: @"(nil-desc)";
}

static BOOL gateKeyInterest(NSString *n) {
    if (!n) return NO;
    return [n rangeOfString:
              @"(?i)(access|jwt|ticket|deviceid|grant|dvntm|ytlite|ytl[_-]|license"
              @"|expiry|plan|premium|patreon|token|signature|verifier|nonce)"
              options:NSRegularExpressionSearch].length != 0;
}

// ---------------------------------------------------------------
// v1 truth-getter spoofer (retained; opt-in YTLiteUnlockSpoof=YES)
// ---------------------------------------------------------------
static BOOL matchesInterest(NSString *n) {
    if (!n) return NO;
    if ([n hasPrefix:@"DVN"] || [n hasPrefix:@"YTP"]) return YES;
    NSArray *pats = @[@"Patreon", @"Supporters", @"Welcome", @"Account",
                      @"Premium", @"License", @"Subscription", @"Entitle",
                      @"Access", @"Login"];
    for (NSString *p in pats)
        if ([n rangeOfString:p options:NSCaseInsensitiveSearch].length)
            return YES;
    return NO;
}

static BOOL isActivationVocabulary(NSString *sel) {
    if (!sel) return NO;
    NSString *s = [sel lowercaseString];
    NSArray *words = @[@"activ", @"valid", @"unlock", @"subscri", @"entitle",
                       @"linked", @"regist", @"limit", @"purchas", @"premiu",
                       @"tier", @"grant", @"signe"];
    for (NSString *w in words)
        if ([s rangeOfString:w].length) return YES;
    return NO;
}

static BOOL isTruthType(char c) {
    return c == 'B' || c == 'c' || c == 'q' || c == 'l' || c == 'i';
}

static BOOL shim_true_BOOL(id self, SEL _cmd)          { return YES; }
static long shim_truthy_long(id self, SEL _cmd)        { return 1; }
static int  shim_truthy_int(id self, SEL _cmd)         { return 1; }
static unsigned char shim_true_char(id self, SEL _cmd) { return 1; }
static unsigned long shim_truthy_ul(id self, SEL _cmd) { return 1; }

static NSMutableSet *hookedSet;
static NSMutableSet *dumpedSet;
static NSMutableSet *interestingClasses;
static NSMutableSet *targetedHooked;

// ---------------------------------------------------------------
// dynamic observe-hook machinery
//   every shim resolves its own orig IMP by _cmd, so a small fixed
//   shim family serves the whole selector table, signature-safe
//   (args logged as raw pointers; returns logged via type kind)
// ---------------------------------------------------------------
typedef struct {
    SEL    sel;
    void  *orig;
} DynEntry;

static DynEntry dynEntries[24];
static int      dynCount = 0;
static long     observeLines = 0;
static BOOL     observeCapWarned = NO;

static BOOL observeCapHit(void) {
    if (observeLines < 800) return NO;
    if (!observeCapWarned) {
        observeCapWarned = YES;
        YLOG(@"observe logging capped at 800 lines (hooks stay installed)");
    }
    return YES;
}

static void *dynOrig(SEL _cmd) {
    for (int i = 0; i < dynCount; i++)
        if (dynEntries[i].sel == _cmd) return dynEntries[i].orig;
    return NULL;
}

static NSString *ownerOf(id self) {
    const char *n = object_getClassName(self);
    return n ? @(n) : @"(unknown)";
}

// void, 0 args
static void dyn_v0(id self, SEL _cmd) {
    void *o = dynOrig(_cmd);
    if (!observeCapHit())
        YLOG(@"OBS -[%@ %@] enter", ownerOf(self), NSStringFromSelector(_cmd));
    if (o) ((void (*)(id, SEL))o)(self, _cmd);
}
// void, 1 arg (raw pointer)
static void dyn_v1(id self, SEL _cmd, void *a0) {
    void *o = dynOrig(_cmd);
    if (!observeCapHit())
        YLOG(@"OBS -[%@ %@] arg0=%p", ownerOf(self), NSStringFromSelector(_cmd), a0);
    if (o) ((void (*)(id, SEL, void *))o)(self, _cmd, a0);
}
// void, 2 args
static void dyn_v2(id self, SEL _cmd, void *a0, void *a1) {
    void *o = dynOrig(_cmd);
    if (!observeCapHit())
        YLOG(@"OBS -[%@ %@] arg0=%p arg1=%p", ownerOf(self), NSStringFromSelector(_cmd), a0, a1);
    if (o) ((void (*)(id, SEL, void *, void *))o)(self, _cmd, a0, a1);
}
// BOOL, 0 args
static BOOL dyn_B0(id self, SEL _cmd) {
    void *o = dynOrig(_cmd);
    BOOL r = o ? ((BOOL (*)(id, SEL))o)(self, _cmd) : NO;
    if (!observeCapHit())
        YLOG(@"OBS -[%@ %@] -> %@", ownerOf(self), NSStringFromSelector(_cmd), r ? @"YES" : @"NO");
    return r;
}
// key-string helper: only called where the method signature guarantees
// an object argument (YTLUserDefaults key params); falls back to hex
static NSString *keyStr(void *p) {
    if (!p) return @"(nil)";
    id obj = (__bridge id)p;
    if ([obj isKindOfClass:[NSString class]]) return obj;
    return [NSString stringWithFormat:@"%p", p];
}

// BOOL, 1 arg (arg is an object in every selector that picks this shim:
// +[YTLUserDefaults boolForKey:])
static BOOL dyn_B1(id self, SEL _cmd, void *a0) {
    void *o = dynOrig(_cmd);
    BOOL r = o ? ((BOOL (*)(id, SEL, void *))o)(self, _cmd, a0) : NO;
    if (!observeCapHit())
        YLOG(@"OBS +[%@ %@] key=%@ -> %@", ownerOf(self), NSStringFromSelector(_cmd),
             keyStr(a0), r ? @"YES" : @"NO");
    return r;
}
// long, 1 arg (long-returning class getter: integerForKey:)
static long dyn_q1(id self, SEL _cmd, void *a0) {
    void *o = dynOrig(_cmd);
    long r = o ? ((long (*)(id, SEL, void *))o)(self, _cmd, a0) : 0;
    if (!observeCapHit())
        YLOG(@"OBS +[%@ %@] key=%@ -> %ld", ownerOf(self), NSStringFromSelector(_cmd),
             keyStr(a0), r);
    return r;
}
// +[YTLUserDefaults setBool:forKey:]  (value, key-object)
static void dlud_setBool2(id self, SEL _cmd, long v, void *key) {
    void *o = dynOrig(_cmd);
    if (!observeCapHit())
        YLOG(@"YTLUD +setBool:forKey: %@ -> %@", keyStr(key), v ? @"YES" : @"NO");
    if (o) ((void (*)(id, SEL, long, void *))o)(self, _cmd, v, key);
}
// +[YTLUserDefaults setInteger:forKey:]
static void dlud_setInt2(id self, SEL _cmd, long v, void *key) {
    void *o = dynOrig(_cmd);
    if (!observeCapHit())
        YLOG(@"YTLUD +setInteger:forKey: %@ -> %ld", keyStr(key), v);
    if (o) ((void (*)(id, SEL, long, void *))o)(self, _cmd, v, key);
}
// id, 0 args
static id dyn_id0(id self, SEL _cmd) {
    void *o = dynOrig(_cmd);
    id r = o ? ((id (*)(id, SEL))o)(self, _cmd) : nil;
    if (!observeCapHit())
        YLOG(@"OBS -[%@ %@] -> %@ (%@)", ownerOf(self), NSStringFromSelector(_cmd),
             clampDesc(r), r ? NSStringFromClass([r class]) : @"nil");
    return r;
}
// id, 1 arg
static id dyn_id1(id self, SEL _cmd, void *a0) {
    void *o = dynOrig(_cmd);
    id r = o ? ((id (*)(id, SEL, void *))o)(self, _cmd, a0) : nil;
    if (!observeCapHit())
        YLOG(@"OBS -[%@ %@] arg0=%p -> %@ (%@)", ownerOf(self), NSStringFromSelector(_cmd), a0,
             clampDesc(r), r ? NSStringFromClass([r class]) : @"nil");
    return r;
}
// id, 2 args
static id dyn_id2(id self, SEL _cmd, void *a0, void *a1) {
    void *o = dynOrig(_cmd);
    id r = o ? ((id (*)(id, SEL, void *, void *))o)(self, _cmd, a0, a1) : nil;
    if (!observeCapHit())
        YLOG(@"OBS -[%@ %@] arg0=%p arg1=%p -> %@ (%@)", ownerOf(self),
             NSStringFromSelector(_cmd), a0, a1, clampDesc(r),
             r ? NSStringFromClass([r class]) : @"nil");
    return r;
}

static void dynRegister(SEL sel, void *orig) {
    if (dynCount < 24) {
        dynEntries[dynCount].sel = sel;
        dynEntries[dynCount].orig = orig;
        dynCount++;
    }
}

// install an observe hook using the runtime type encoding
static void installObserve(Class cls, SEL sel, NSString *owner, BOOL isClassMethod) {
    Method m = isClassMethod ? class_getClassMethod(cls, sel) : class_getInstanceMethod(cls, sel);
    if (!m) {
        YLOG(@"OBS hook absent: %c[%@ %@]", isClassMethod ? '+' : '-', owner, NSStringFromSelector(sel));
        return;
    }
    const char *ty = method_getTypeEncoding(m);
    unsigned int n = method_getNumberOfArguments(m);
    n = (n >= 2) ? (n - 2) : 0;
    IMP shim = NULL;
    if (ty) {
        char r = ty[0];
        if (r == 'v')        shim = (n == 0) ? (IMP)dyn_v0 : (n == 1) ? (IMP)dyn_v1 : (n == 2) ? (IMP)dyn_v2 : NULL;
        else if (r == '@')   shim = (n == 0) ? (IMP)dyn_id0 : (n == 1) ? (IMP)dyn_id1 : (n == 2) ? (IMP)dyn_id2 : NULL;
        else if (r == 'B' || r == 'c') shim = (n == 0) ? (IMP)dyn_B0 : (n == 1) ? (IMP)dyn_B1 : NULL;
        else if (r == 'q' || r == 'l' || r == 'i' || r == 'Q' || r == 'L' || r == 'I')
            shim = (n <= 1) ? (IMP)dyn_q1 : NULL;
        if (!shim) {
            YLOG(@"OBS hook skipped (unsupported enc %s, %u args): [%@ %@]", ty, n, owner, NSStringFromSelector(sel));
            return;
        }
    } else {
        YLOG(@"OBS hook skipped (no encoding): [%@ %@]", owner, NSStringFromSelector(sel));
        return;
    }
    IMP old = NULL;
    Class targetCls = isClassMethod ? object_getClass(cls) : cls;
    MSHookMessageEx(targetCls, sel, shim, &old);
    dynRegister(sel, old);
    YLOG(@"OBS hook installed %c[%@ %@] enc=%s args=%u", isClassMethod ? '+' : '-', owner,
         NSStringFromSelector(sel), ty, n);
}

static const char *kObserveTable[][2] = {
    { "YTPDownloadsVC",    "setupLockView"                              },
    { "YTPDownloadsVC",    "unlockTapped"                               },
    { "YTPDownloadsVC",    "lockPrivate"                                },
    { "YTPDownloadsVC",    "applyLockState"                             },
    { "YTPDownloadsVC",    "isPrivateLocked"                            },
    { "YTPDownloadsVC",    "isPrivateContext"                           },
    { "YTPSettingsBuilder", "patreonSection:"                           },
    { "YTPSettingsBuilder", "patreonStatusCell"                         },
    { "YTPSettingsBuilder", "patreonButtonCellWithType:model:"          },
    { "DVNPatreonContext",  "presentationAnchorForWebAuthenticationSession:" },
};

static void installTargetedHooks(NSString *name, Class cls) {
    if (!cls || [targetedHooked containsObject:name]) return;
    [targetedHooked addObject:name];
    for (unsigned long i = 0; i < sizeof(kObserveTable) / sizeof(kObserveTable[0]); i++) {
        if ([name isEqualToString:@(kObserveTable[i][0])]) {
            installObserve(cls, NSSelectorFromString(@(kObserveTable[i][1])), name, NO);
        }
    }
    if ([name isEqualToString:@"YTLUserDefaults"]) {
        installObserve(cls, NSSelectorFromString(@"boolForKey:"),        name, YES);
        installObserve(cls, NSSelectorFromString(@"integerForKey:"),     name, YES);
        SEL sb = NSSelectorFromString(@"setBool:forKey:");
        SEL si = NSSelectorFromString(@"setInteger:forKey:");
        if (class_getClassMethod(cls, sb)) {
            IMP old = NULL;
            MSHookMessageEx(object_getClass(cls), sb, (IMP)dlud_setBool2, &old);
            dynRegister(sb, old);
            YLOG(@"YTLUD +setBool:forKey: hook installed");
        }
        if (class_getClassMethod(cls, si)) {
            IMP old = NULL;
            MSHookMessageEx(object_getClass(cls), si, (IMP)dlud_setInt2, &old);
            dynRegister(si, old);
            YLOG(@"YTLUD +setInteger:forKey: hook installed");
        }
    }
}

// ---------------------------------------------------------------
// gate function: fingerprint locate + transparent hook (+ crack trial)
// ---------------------------------------------------------------
static void *orig_gate = NULL;
static long  gateCalls = 0;
static BOOL  gateHookInstalled = NO;

// crack-trial override: set NSUD key YTLiteUnlockForceGate to a decimal
// integer BEFORE launch; every gate call returns that raw value (w0).
// Absent/-1 = transparent pass-through (recon only). NOTE: a wrong
// override can crash the first consumer that dereferences it — the
// GATE-FORCE lines show exactly which call did it. Mode changes need a
// relaunch (cached once, same pattern as the spoof key).
static long gateForceMode(void) {
    static long cached = -2;   // -2 = not read yet
    if (cached == -2) {
        id v = [[NSUserDefaults standardUserDefaults] objectForKey:@"YTLiteUnlockForceGate"];
        cached = (v == nil) ? -1 : [v longLongValue];
    }
    return cached;
}

static void *hook_gate(void *a0, void *a1, void *a2, void *a3) {
    void *r = ((void *(*)(void *, void *, void *, void *))orig_gate)(a0, a1, a2, a3);
    gateCalls++;
    long mode = gateForceMode();
    BOOL forced = (mode >= 0);
    void *fr = forced ? (void *)(intptr_t)mode : r;
    if (!forced) {
        // transparent recon: full log for the first 200, every 20th after
        if (gateCalls <= 200 || (gateCalls % 20) == 0) {
            YLOG(@"GATE #%ld fn=%p args a0=%p a1=%p a2=%p a3=%p ret=0x%llx (int=%lld)",
                 (long)gateCalls, orig_gate, a0, a1, a2, a3,
                 (unsigned long long)(uintptr_t)r, (long long)(intptr_t)r);
        } else if (gateCalls == 201) {
            YLOG(@"GATE logging reduced to every 20th call (first 200 fully logged)");
        }
    } else {
        // crack trial: log every forced call (bows out at the cap)
        if (gateCalls <= 1000 && !observeCapHit()) {
            YLOG(@"GATE-FORCE #%ld mode=%ld args a0=%p a1=%p a2=%p a3=%p orig=0x%llx(int=%lld) -> FORCED=0x%llx(int=%lld)",
                 (long)gateCalls, mode, a0, a1, a2, a3,
                 (unsigned long long)(uintptr_t)r, (long long)(intptr_t)r,
                 (unsigned long long)(uintptr_t)fr, (long long)(intptr_t)fr);
        }
    }
    return fr;
}

static void locateAndHookGate(NSString *phase) {
    if (gateHookInstalled) return;
    if (&MSHookFunction == NULL) {
        static BOOL weakWarned = NO;
        if (!weakWarned) {
            weakWarned = YES;
            YLOG(@"MSHookFunction weak symbol is NULL — gate hook skipped, other recon continues");
        }
        return;
    }
    uint32_t imgCount = _dyld_image_count();
    for (uint32_t i = 0; i < imgCount; i++) {
        const char *cpath = _dyld_get_image_name(i);
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!cpath || !hdr) continue;
        unsigned long sz = 0;
        uint32_t *text = (uint32_t *)getsectiondata(hdr, "__TEXT", "__text", &sz);
        if (!text || sz < 0x100000) continue;
        NSString *path = [NSString stringWithUTF8String:cpath];
        if (!path) continue;
        BOOL named = [[path.lastPathComponent lowercaseString] containsString:@"ytlite"];
        uint32_t first = kGateFP[0];
        for (unsigned long off = 0; off + 64 <= sz; off += 4) {
            if (text[off >> 2] != first) continue;
            if (memcmp((uint8_t *)text + off, kGateFP, sizeof(kGateFP)) != 0) continue;
            uint32_t *fn = (uint32_t *)((uint8_t *)text + off - 0x20);
            if (memcmp(fn, kGatePrologue, sizeof(kGatePrologue)) != 0) {
                YLOG(@"GATE fingerprint matched at %p (%@) but prologue mismatch — ignored", fn, path.lastPathComponent);
                continue;
            }
            YLOG(@"GATE FOUND: image=%p fn=%p (%@, %s)", hdr, fn, path.lastPathComponent,
                 named ? "named" : "fallback");
            MSHookFunction((void *)fn, (void *)hook_gate, &orig_gate);
            gateHookInstalled = YES;
            long mode = gateForceMode();
            YLOG(@"GATE HOOK installed (phase %@)%@ — %s", phase,
                 mode >= 0 ? [NSString stringWithFormat:@" force mode=%ld ACTIVE", mode] : @"",
                 mode >= 0 ? "crack trial live" : "returns will be logged");
            return;
        }
        if (named) {
            YLOG(@"GATE scan done on %@ (%lu MB of text) — no fingerprint match!", path.lastPathComponent, sz >> 20);
        }
    }
}

// ---------------------------------------------------------------
// prefs + keychain dumps (definitions after decl, called from timer)
// ---------------------------------------------------------------
static void dumpPrefs(NSString *phase);
static void keychainProbe(void);
static void scanOnce(NSString *phase);

static void startRescans(void) {
    __block NSInteger ticks = 0;
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                                     dispatch_get_main_queue());
    dispatch_source_set_timer(timer,
        dispatch_time(DISPATCH_TIME_NOW, 0.6 * NSEC_PER_SEC),
        1.0 * NSEC_PER_SEC, 0.3 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        ticks++;
        NSString *phase = [NSString stringWithFormat:@"tick %ld", (long)ticks];
        scanOnce(phase);
        if (ticks <= 13 && (ticks == 1 || ticks == 2 || ticks == 3 || ticks == 5 || ticks == 8 || ticks == 13))
            locateAndHookGate(phase);
        if (ticks == 8 || ticks == 50 || ticks == 120) dumpPrefs([NSString stringWithFormat:@"t%ld", (long)ticks]);
        if (ticks == 15) keychainProbe();
        if (ticks >= 300) {
            dispatch_suspend(timer);
            YLOG(@"scan loop finished; hooks remain installed; gate calls seen=%ld", (long)gateCalls);
        }
    });
    dispatch_resume(timer);
}

static void dumpPrefs(NSString *phase) {
    @try {
        CFDictionaryRef d = CFPreferencesCopyMultiple(NULL, CFSTR("com.dvntm.ytlite"),
                                                      kCFPreferencesCurrentUser,
                                                      kCFPreferencesAnyHost);
        if (d) {
            NSDictionary *dict = CFBridgingRelease(d);
            if (dict.count == 0) {
                YLOG(@"CFPREFS[%@] com.dvntm.ytlite: empty", phase);
            } else {
                for (NSString *k in dict) {
                    NSString *v = clampDesc(dict[k]);
                    if (v.length > 96) v = [[v substringToIndex:96] stringByAppendingString:@"…"];
                    YLOG(@"CFPREFS[%@] %@ = %@", phase, k, v);
                }
            }
        } else {
            YLOG(@"CFPREFS[%@] com.dvntm.ytlite: nil", phase);
        }
    } @catch (__unused id e) {
        YLOG(@"CFPREFS[%@] dump failed", phase);
    }
    @try {
        NSDictionary *all = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        __block int cap = 140;
        for (NSString *k in all) {
            if (cap-- <= 0) break;
            if (gateKeyInterest(k)) {
                NSString *v = clampDesc(all[k]);
                if (v.length > 96) v = [[v substringToIndex:96] stringByAppendingString:@"…"];
                YLOG(@"NSUD-DOMAIN[%@] %@ = %@", phase, k, v);
            }
        }
        YLOG(@"NSUD-DOMAIN[%@] total keys=%lu", phase, (unsigned long)all.count);
    } @catch (__unused id e) {}
    @try {
        Class yc = NSClassFromString(@"YTLUserDefaults");
        SEL sud = NSSelectorFromString(@"standardUserDefaults");
        if (yc && [yc respondsToSelector:sud]) {
            id inst = ((id (*)(id, SEL))objc_msgSend)(yc, sud);
            SEL dr = NSSelectorFromString(@"dictionaryRepresentation");
            if (inst && [inst respondsToSelector:dr]) {
                NSDictionary *dd = ((id (*)(id, SEL))objc_msgSend)(inst, dr);
                __block int cap = 60;
                for (NSString *k in dd) {
                    if (cap-- <= 0) break;
                    if (gateKeyInterest(k)) YLOG(@"YTLUD-DOMAIN[%@] %@ = %@", phase, k, clampDesc(dd[k]));
                }
                YLOG(@"YTLUD-DOMAIN[%@] captured (total %lu keys)", phase, (unsigned long)dd.count);
            } else {
                YLOG(@"YTLUD-DOMAIN[%@] standard UserDefaults instance obtained, no dict (class=%@)",
                     phase, NSStringFromClass([inst class]));
            }
        } else {
            YLOG(@"YTLUD-DOMAIN[%@] YTLUserDefaults class unavailable", phase);
        }
    } @catch (__unused id e) {}
}

static void keychainProbe(void) {
    @try {
        NSDictionary *q = @{
            (id)kSecClass: (id)kSecClassGenericPassword,
            (id)kSecReturnAttributes: @YES,
            (id)kSecReturnData: @YES,
            (id)kSecMatchLimit: (id)kSecMatchLimitAll,
        };
        CFTypeRef out = NULL;
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
        if (st != errSecSuccess || !out) {
            YLOG(@"KEYCHAIN probe: status=%d %@", (int)st,
                 st == errSecItemNotFound ? @"(no items)" : @"");
            return;
        }
        NSArray *items = CFBridgingRelease(out);
        YLOG(@"KEYCHAIN probe: %lu generic-password items", (unsigned long)items.count);
        int cap = 40;
        for (NSDictionary *it in items) {
            if (cap-- <= 0) break;
            NSString *svc = it[(id)kSecAttrService] ?: @"(nil)";
            NSString *acc = it[(id)kSecAttrAccount] ?: @"(nil)";
            NSString *hay = [NSString stringWithFormat:@"%@|%@", svc, acc].lowercaseString;
            if (![hay containsString:@"dvn"] && ![hay containsString:@"ytl"] &&
                ![hay containsString:@"access"] && ![hay containsString:@"token"]) continue;
            NSData *data = it[(id)kSecValueData];
            NSMutableString *hex = [NSMutableString string];
            if (data.length) {
                const unsigned char *b = data.bytes;
                NSUInteger n = MIN(data.length, (NSUInteger)24);
                for (NSUInteger i = 0; i < n; i++) [hex appendFormat:@"%02x", b[i]];
            }
            YLOG(@"KEYCHAIN svc=%@ acc=%@ len=%lu head=%@", svc, acc,
                 (unsigned long)data.length, hex);
        }
    } @catch (__unused id e) {
        YLOG(@"KEYCHAIN probe failed");
    }
}

// ---------------------------------------------------------------
// class scanning (v1 machinery + targeted observe hooks + gate locate)
// ---------------------------------------------------------------
static void processClass(Class cls) {
    NSString *name = NSStringFromClass(cls);
    if (!name || [name hasPrefix:@"_"]) return;
    if (![interestingClasses containsObject:name]) return;
    if ([dumpedSet containsObject:name]) return;
    [dumpedSet addObject:name];

    installTargetedHooks(name, cls);

    unsigned int mCount = 0;
    Method *methods = class_copyMethodList(cls, &mCount);
    YLOG(@"class %@ (super=%@) %u methods", name,
         class_getSuperclass(cls) ? NSStringFromClass(class_getSuperclass(cls)) : @"nil",
         mCount);

    for (unsigned int m = 0; m < mCount; m++) {
        Method mm = methods[m];
        SEL sel = method_getName(mm);
        const char *ty = method_getTypeEncoding(mm);
        unsigned int nArgs = method_getNumberOfArguments(mm);
        NSString *selName = NSStringFromSelector(sel);
        BOOL isGetter = (nArgs <= 2);
        BOOL isTruth  = isGetter && ty && isTruthType(ty[0]);

        YLOG(@"  method %@ args=%u types=%s%@", selName, nArgs, ty ?: "?", isGetter ? @" (getter)" : @"");
        if (spoofEnabled() && isTruth && isActivationVocabulary(selName)) {
            NSString *hookKeyPath = [NSString stringWithFormat:@"%@/%@", name, selName];
            if ([hookedSet containsObject:hookKeyPath]) continue;
            [hookedSet addObject:hookKeyPath];
            IMP shim = NULL;
            switch (ty[0]) {
                case 'B': shim = (IMP)shim_true_BOOL;     break;
                case 'c': shim = (IMP)shim_true_char;     break;
                case 'q':
                case 'l': shim = (IMP)shim_truthy_long;   break;
                case 'i': shim = (IMP)shim_truthy_int;    break;
                case 'I': case 'L': case 'Q': shim = (IMP)shim_truthy_ul; break;
                default: break;
            }
            if (!shim) continue;
            IMP *old = malloc(sizeof(IMP));
            *old = NULL;
            MSHookMessageEx(cls, sel, shim, old);
            YLOG(@"SPOOF -[%@ %@] forced %@", name, selName, (ty[0] == 'B' ? @"YES" : @"1"));
        }
    }
    free(methods);
}

static void scanOnce(NSString *phase) {
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    if (!classes) return;
    for (unsigned int i = 0; i < count; i++) {
        Class c = classes[i];
        if (class_isMetaClass(c)) continue;
        NSString *name = NSStringFromClass(c);
        if (name && matchesInterest(name)) {
            if (![interestingClasses containsObject:name]) {
                YLOG(@"NEW interesting class discovered at %@: %@", phase, name);
                [interestingClasses addObject:name];
            }
        }
    }
    static BOOL probed = NO;
    if (!probed && count) {
        probed = YES;
        SEL probe = NSSelectorFromString(@"verifyAccessWithCompletion:");
        for (unsigned int i = 0; i < count; i++) {
            Class c = classes[i];
            if (class_isMetaClass(c)) continue;
            if (class_getInstanceMethod(c, probe)) {
                NSString *gname = NSStringFromClass(c);
                YLOG(@"GATE OWNER: %@ implements verifyAccessWithCompletion: (super=%@)",
                     gname,
                     class_getSuperclass(c) ? NSStringFromClass(class_getSuperclass(c)) : @"nil");
                [interestingClasses addObject:gname];
                processClass(c);
            }
        }
    }
    YLOG(@"scan (%@): %u classes, %lu interesting, %lu dumped", phase, count,
         (unsigned long)interestingClasses.count, (unsigned long)dumpedSet.count);
    for (NSString *name in [interestingClasses copy]) {
        Class c = NSClassFromString(name);
        if (c) processClass(c);
    }
    free(classes);
}

// ---------------------------------------------------------------
// NSUserDefaults sniffers (read + write)
// ---------------------------------------------------------------
static IMP orig_NSUD_objectForKey = NULL;
static long nsudLogged = 0;

static id sniff_NSUD_objectForKey(id self, SEL _cmd, NSString *key) {
    id v = ((id(*)(id, SEL, NSString *))orig_NSUD_objectForKey)(self, _cmd, key);
    if ([key isKindOfClass:[NSString class]]) {
        nsudLogged++;
        if (nsudLogged <= 200 && gateKeyInterest(key)) {
            YLOG(@"NSUD read key=%@ val=%@", key, v);
        }
    }
    return v;
}
static IMP orig_NSUD_setObject = NULL;
static void sniff_NSUD_setObject(id self, SEL _cmd, id v, NSString *key) {
    if ([key isKindOfClass:[NSString class]])
        YLOG(@"NSUD WRITE key=%@ val=%@ (%@)", key, clampDesc(v),
             v ? NSStringFromClass([v class]) : @"nil");
    ((void(*)(id, SEL, id, NSString *))orig_NSUD_setObject)(self, _cmd, v, key);
}
static IMP orig_NSUD_removeObject = NULL;
static void sniff_NSUD_removeObject(id self, SEL _cmd, NSString *key) {
    if ([key isKindOfClass:[NSString class]]) YLOG(@"NSUD REMOVE key=%@", key);
    ((void(*)(id, SEL, NSString *))orig_NSUD_removeObject)(self, _cmd, key);
}

%ctor {
    hookedSet          = [NSMutableSet new];
    dumpedSet          = [NSMutableSet new];
    interestingClasses = [NSMutableSet new];
    targetedHooked     = [NSMutableSet new];

    YLOG(@"v2.1 (recon + crack trial) start (spoof=%d) app=%@", spoofEnabled(),
          [NSBundle mainBundle].bundleIdentifier ?: @"(unknown)");
    YLOG(@"gate fingerprint u32[0]=0x%08x, MSHookFunction present=%d", kGateFP[0], &MSHookFunction != NULL);

    Class nsud = objc_getClass("NSUserDefaults");
    if (nsud) {
        MSHookMessageEx(nsud, NSSelectorFromString(@"objectForKey:"),
                        (IMP)sniff_NSUD_objectForKey, &orig_NSUD_objectForKey);
        MSHookMessageEx(nsud, NSSelectorFromString(@"setObject:forKey:"),
                        (IMP)sniff_NSUD_setObject, &orig_NSUD_setObject);
        MSHookMessageEx(nsud, NSSelectorFromString(@"removeObjectForKey:"),
                        (IMP)sniff_NSUD_removeObject, &orig_NSUD_removeObject);
        YLOG(@"NSUserDefaults read+write sniffers installed");
    }

    startRescans();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        scanOnce(@"late");
    });
}
