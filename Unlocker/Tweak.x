#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <substrate.h>

// =====================================================================
// YTLiteUnlock — v1 "instrument + light spoof"
//
// Runs alongside the official YTLite.dylib, whose entitlement classes
// (DVNPatreonContext et al.) are *registered at runtime*, not statically
// compiled into the binary's ObjC class list (verified by offline
// parsing — see tools/classdump.py).
//
// Behaviour:
//  1. Periodically rescans the runtime class list for gate-related
//     classes and dumps their full method lists (type encodings included)
//     under an easy-to-grep [YULU] tag.
//  2. For those classes, installs hooks on zero-arg getters whose
//     return type is truth-like (B/c/q/l/i) and whose name matches the
//     activation vocabulary, forcing them to "yes". This mirrors the
//     spoof the community cracks exhibit; it is deliberately narrow to
//     limit collateral damage and every hook is logged.
//  3. The spoofer can be disabled globally with an NSUserDefaults
//     boolean key: YTLiteUnlockSpoof = NO
//
// All output is prefixed [YULU]; read with `idevicesyslog | grep YULU`.
// =====================================================================

static NSString * const kTag = @"[YULU]";
static NSString * const kSpooferKey = @"YTLiteUnlockSpoof";

#define YLOG(...) do { NSLog(@"%@ %@", kTag, [NSString stringWithFormat:__VA_ARGS__]); } while (0)

static BOOL spoofEnabled(void) {
    id v = [[NSUserDefaults standardUserDefaults] objectForKey:kSpooferKey];
    if (v == nil) return YES;
    return [v boolValue];
}

static BOOL matchesInterest(NSString *n) {
    if (!n) return NO;
    NSArray *pats = @[@"DVNPatreon", @"DVNValueStore", @"DVNSupporters",
                      @"WelcomeVC", @"Patreon"];
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

// --- shim IMPs (zero-arg getters only; one IMP serves every hook) ---
static BOOL shim_true_BOOL(id self, SEL _cmd)     { return YES; }
static long shim_truthy_long(id self, SEL _cmd)   { return 1; }
static int  shim_truthy_int(id self, SEL _cmd)    { return 1; }
static unsigned char shim_true_char(id self, SEL _cmd) { return 1; }
static unsigned long shim_truthy_ul(id self, SEL _cmd) { return 1; }

static NSMutableSet *hookedSet;
static NSMutableSet *dumpedSet;
static NSMutableSet *interestingClasses;

static void processClass(Class cls) {
    NSString *name = NSStringFromClass(cls);
    if (!name || [name hasPrefix:@"_"]) return;
    if (![interestingClasses containsObject:name]) return;
    if ([dumpedSet containsObject:name]) return;
    [dumpedSet addObject:name];

    unsigned int mCount = 0;
    Method *methods = class_copyMethodList(cls, &mCount);
    YLOG(@"class %@ (super=%@) %u methods", name,
         cls.superclass ? NSStringFromClass(cls.superclass) : @"nil", mCount);

    for (unsigned int m = 0; m < mCount; m++) {
        Method mm = methods[m];
        SEL sel = method_getName(mm);
        const char *ty = method_getTypeEncoding(mm);
        unsigned int nArgs = method_getNumberOfArguments(mm);
        NSString *selName = NSStringFromSelector(sel);
        BOOL isGetter = (nArgs <= 2);
        BOOL isTruth  = isGetter && ty && isTruthType(ty[0]);

        YLOG(@"  method %@ args=%u types=%s%@",
             selName, nArgs, ty ?: "?", isGetter ? @" (getter)" : @"");

        if (isTruth && isActivationVocabulary(selName)) {
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
            YLOG(@"SPOOF -[%@ %@] forced %@", name, selName,
                 (ty[0] == 'B' ? @"YES" : @"1"));
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
        if (name && matchesInterest(name))
            [interestingClasses addObject:name];
    }

    YLOG(@"scan (%@): %u classes, %lu interesting, %lu dumped",
         phase, count, (unsigned long)interestingClasses.count, (unsigned long)dumpedSet.count);

    for (NSString *name in [interestingClasses copy]) {
        Class c = NSClassFromString(name);
        if (c) processClass(c);
    }
    free(classes);
}

static void startRescans(void) {
    __block NSInteger ticks = 0;
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                                     dispatch_get_main_queue());
    dispatch_source_set_timer(timer,
        dispatch_time(DISPATCH_TIME_NOW, 0.6 * NSEC_PER_SEC),
        1.0 * NSEC_PER_SEC,
        0.3 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        ticks++;
        scanOnce([NSString stringWithFormat:@"tick %ld", (long)ticks]);
        if (ticks >= 45) {      // stop rescans after ~45 s; hooks stay installed
            dispatch_suspend(timer);
            YLOG(@"scan loop finished; hooks remain installed");
        }
    });
    dispatch_resume(timer);
}

%ctor {
    hookedSet          = [NSMutableSet new];
    dumpedSet          = [NSMutableSet new];
    interestingClasses = [NSMutableSet new];

    YLOG(@"v1 start (spoof=%d) app=%@", spoofEnabled(),
          [NSBundle mainBundle].bundleIdentifier ?: @"(unknown)"]));

    startRescans();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        scanOnce(@"late");
    });
}
