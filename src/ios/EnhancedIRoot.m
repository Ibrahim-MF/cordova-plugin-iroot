#import "EnhancedIRoot.h"
#import <sys/stat.h>
#import <string.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <sys/syscall.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <sys/utsname.h>
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <pthread.h>
#import <math.h>

@interface EnhancedIRoot ()

@property (nonatomic, strong) NSTimer *monitoringTimer;
@property (nonatomic, strong) NSDictionary *enabledChecks;
@property (nonatomic, strong) NSArray *jailbreakPaths;
@property (nonatomic, strong) NSArray *jailbreakBinaries;
@property (nonatomic, strong) NSArray *jailbreakSchemes;
@property (nonatomic, strong) NSArray *suspiciousLibraries;
@property (nonatomic, strong) NSArray *objectionArtifacts;
@property (nonatomic, strong) NSData *integrityChecksum;
@property (nonatomic, strong) NSTimer *integrityTimer;
@property (nonatomic, assign) BOOL backgroundFridaDbusHit;
@property (nonatomic, assign) BOOL backgroundFridaScanStarted;
@property (nonatomic, strong) NSMutableDictionary<NSString*, NSValue*> *runtimeMethodIMPs;
@property (nonatomic, strong) NSMutableDictionary<NSString*, NSData*> *runtimeMethodChecksums;

@end

static volatile BOOL EnhancedIRootSuspiciousDyldImageSeen = NO;
static char EnhancedIRootSuspiciousDyldImageName[512] = {0};

static BOOL EnhancedIRootImageNameContainsInstrumentationToken(const char* imageName) {
    if (imageName == NULL) {
        return NO;
    }

    const char* tokens[] = {
        "frida",
        "gum-js",
        "gumjs",
        "frida-gadget",
        "linjector",
        "objection",
        "cycript",
        "substrate",
        "substitute",
        "ellekit",
        "libhooker"
    };

    for (int i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
        if (strcasestr(imageName, tokens[i]) != NULL) {
            return YES;
        }
    }

    return NO;
}

static void EnhancedIRootDyldImageAdded(const struct mach_header* header, intptr_t slide) {
    (void)slide;
    uint32_t imageCount = _dyld_image_count();

    for (uint32_t i = 0; i < imageCount; i++) {
        if (_dyld_get_image_header(i) != header) {
            continue;
        }

        const char* imageName = _dyld_get_image_name(i);
        if (EnhancedIRootImageNameContainsInstrumentationToken(imageName)) {
            EnhancedIRootSuspiciousDyldImageSeen = YES;
            if (imageName != NULL) {
                strncpy(EnhancedIRootSuspiciousDyldImageName, imageName, sizeof(EnhancedIRootSuspiciousDyldImageName) - 1);
                EnhancedIRootSuspiciousDyldImageName[sizeof(EnhancedIRootSuspiciousDyldImageName) - 1] = '\0';
            }
            return;
        }
    }
}

@implementation EnhancedIRoot {
    dispatch_semaphore_t _fridaScanSemaphore;
}

- (void)pluginInitialize {
    [super pluginInitialize];
    
    // Initialize integrity checksum
    self.integrityChecksum = [self calculateIntegrityChecksum];
    _fridaScanSemaphore = dispatch_semaphore_create(0);

    // Start periodic integrity checks
    self.integrityTimer = [NSTimer scheduledTimerWithTimeInterval:30.0
                                                         target:self
                                                       selector:@selector(checkIntegrity)
                                                       userInfo:nil
                                                        repeats:YES];

    self.monitoringTimer = [NSTimer scheduledTimerWithTimeInterval:10.0
                                                           target:self
                                                         selector:@selector(runRuntimeSentinelChecks)
                                                         userInfo:nil
                                                          repeats:YES];

    [self initializeRuntimeIntegrityBaselines];
    _dyld_register_func_for_add_image(EnhancedIRootDyldImageAdded);

    // Initialize jailbreak detection paths
    self.jailbreakPaths = @[
        @"/Applications/Cydia.app",
        @"/Applications/Sileo.app",
        @"/Applications/Zebra.app",
        @"/Applications/FakeCarrier.app",
        @"/Applications/Icy.app",
        @"/Applications/IntelliScreen.app",
        @"/Applications/MxTube.app",
        @"/Applications/RockApp.app",
        @"/Applications/SBSettings.app",
        @"/Applications/WinterBoard.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        @"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        @"/private/var/lib/apt",
        @"/private/var/lib/cydia",
        @"/private/var/mobile/Library/SBSettings/Themes",
        @"/private/var/stash",
        @"/private/var/tmp/cydia.log",
        @"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        @"/usr/bin/sshd",
        @"/usr/libexec/sftp-server",
        @"/usr/sbin/sshd",
        @"/etc/apt",
        @"/etc/ssh/sshd_config",
        @"/var/cache/apt",
        @"/var/lib/apt",
        @"/var/lib/cydia",
        @"/var/log/syslog",
        @"/var/tmp/cydia.log",
        @"/var/jb",
        @"/var/jb/Applications/Sileo.app",
        @"/var/jb/Applications/Zebra.app",
        @"/var/jb/Library/MobileSubstrate",
        @"/var/jb/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/var/jb/Library/TweakInject",
        @"/var/jb/usr/bin",
        @"/var/jb/usr/sbin",
        @"/var/jb/usr/lib/TweakInject",
        @"/var/jb/etc/apt",
        @"/var/jb/var/lib/apt",
        @"/var/jb/var/lib/dpkg",
        @"/procursus",
        @"/private/preboot"
    ];
    
    // Initialize jailbreak binaries
    self.jailbreakBinaries = @[
        @"/bin/bash",
        @"/bin/sh",
        @"/usr/sbin/sshd",
        @"/usr/bin/sshd",
        @"/usr/sbin/sshd",
        @"/usr/bin/ssh",
        @"/usr/local/bin/ssh",
        @"/usr/bin/scp",
        @"/usr/bin/sftp",
        @"/usr/bin/ssh-keygen",
        @"/usr/bin/ssh-add",
        @"/usr/bin/ssh-agent",
        @"/usr/bin/ssh-keyscan",
        @"/usr/bin/ssh-keysign",
        @"/usr/bin/ssh-argv0",
        @"/usr/bin/ssh-copy-id",
        @"/usr/bin/ssh-askpass",
        @"/usr/bin/ssh-askpass2",
        @"/usr/bin/ssh-askpass3",
        @"/usr/bin/ssh-askpass4"
    ];
    
    // Initialize jailbreak schemes
    self.jailbreakSchemes = @[
        @"cydia",
        @"sileo",
        @"zbra",
        @"filza",
        @"activator"
    ];
    
    // Initialize suspicious libraries
    self.suspiciousLibraries = @[
        @"frida",
        @"cynject",
        @"libcycript",
        @"libsubstitute",
        @"substrate",
        @"substitute",
        @"RevealServer",
        @"libReveal",
        @"libcycript",
        @"libobjection",
        @"objection"
    ];
    
    // Initialize Objection artifacts
    self.objectionArtifacts = @[
        @"/var/root/objection",
        @"/var/mobile/objection",
        @"/var/root/.objection",
        @"/var/mobile/.objection",
        @"/var/root/.objection-agent",
        @"/var/mobile/.objection-agent",
        @"/var/root/.objection-agent.js",
        @"/var/mobile/.objection-agent.js"
    ];
}

#pragma mark - Public Methods

- (void)configure:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = nil;
    
    @try {
        NSDictionary* options = [command.arguments objectAtIndex:0];
        self.enabledChecks = options;
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    } @catch (NSException* exception) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)checkDeviceIntegrity:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;
        
        @try {
            NSMutableDictionary* result = [NSMutableDictionary dictionary];
            [result addEntriesFromDictionary:[self checkJailbreak]];
            [result addEntriesFromDictionary:[self checkHookingFrameworks]];
            [result addEntriesFromDictionary:[self checkDebugger]];
            [result addEntriesFromDictionary:[self checkAppIntegrity]];
            
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        } @catch (NSException* exception) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
        }
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)checkJailbreak:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;
        
        @try {
            NSDictionary* result = [self checkJailbreak];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        } @catch (NSException* exception) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
        }
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)checkRoot:(CDVInvokedUrlCommand*)command {
    [self checkJailbreak:command];
}

- (void)checkEmulator:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;

        @try {
            NSDictionary* result = [self checkEmulator];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        } @catch (NSException* exception) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
        }

        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)checkHookingFrameworks:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;
        
        @try {
            NSDictionary* result = [self checkHookingFrameworks];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        } @catch (NSException* exception) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
        }
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)checkDebugger:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;
        
        @try {
            NSDictionary* result = [self checkDebugger];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        } @catch (NSException* exception) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
        }
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)checkAppIntegrity:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;
        
        @try {
            NSDictionary* result = [self checkAppIntegrity];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        } @catch (NSException* exception) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
        }
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)startMonitoring:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = nil;
    
    @try {
        if (self.monitoringTimer) {
            [self.monitoringTimer invalidate];
        }
        
        NSDictionary* options = [command.arguments objectAtIndex:0];
        NSTimeInterval interval = [[options objectForKey:@"interval"] doubleValue] ?: 5.0;
        
        self.monitoringTimer = [NSTimer scheduledTimerWithTimeInterval:interval
                                                              target:self
                                                            selector:@selector(runMonitoringChecks)
                                                            userInfo:nil
                                                             repeats:YES];
        
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    } @catch (NSException* exception) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)stopMonitoring:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = nil;
    
    @try {
        if (self.monitoringTimer) {
            [self.monitoringTimer invalidate];
            self.monitoringTimer = nil;
        }
        
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    } @catch (NSException* exception) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)getThreatReport:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;
        
        @try {
            NSMutableDictionary* report = [NSMutableDictionary dictionary];
            report[@"deviceIntegrity"] = [self checkJailbreak];
            report[@"hookingFrameworks"] = [self checkHookingFrameworks];
            report[@"debugger"] = [self checkDebugger];
            report[@"emulator"] = [self checkEmulator];
            report[@"appIntegrity"] = [self checkAppIntegrity];
            
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:report];
        } @catch (NSException* exception) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
        }
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)getSignals:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;

        @try {
            NSDictionary* jailbreak = [self checkJailbreak];
            NSDictionary* hooking = [self checkHookingFrameworks];
            NSDictionary* debugger = [self checkDebugger];
            NSDictionary* emulator = [self checkEmulator];
            NSDictionary* integrity = [self checkAppIntegrity];

            BOOL rooted = [jailbreak[@"isJailbroken"] boolValue];
            BOOL isEmulator = [emulator[@"isEmulator"] boolValue];
            BOOL hooked = [hooking[@"isHooked"] boolValue] || [debugger[@"isDebuggerAttached"] boolValue];
            BOOL tampered = [integrity[@"isTampered"] boolValue];
            BOOL isCompromised = rooted || isEmulator || hooked || tampered;

            if (!isCompromised) {
                [self waitForBackgroundFridaScan:8.0];
                if ([self checkFridaPorts]) {
                    hooked = YES;
                    isCompromised = YES;
                }
            }

            NSMutableDictionary* result = [NSMutableDictionary dictionary];
            result[@"isRooted"] = @(rooted);
            result[@"isEmulator"] = @(isEmulator);
            result[@"isHooked"] = @(hooked);
            result[@"isTampered"] = @(tampered);
            result[@"isCompromised"] = @(isCompromised);
            if (hooking[@"riskScore"] != nil) {
                result[@"riskScore"] = hooking[@"riskScore"];
            }

            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        } @catch (NSException* exception) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
        }

        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

#pragma mark - Private Methods

- (void)runMonitoringChecks {
    @try {
        NSMutableDictionary* report = [NSMutableDictionary dictionary];
        
        if (!self.enabledChecks || [self.enabledChecks[@"checkJailbreak"] boolValue]) {
            NSDictionary* jailbreakCheck = [self checkJailbreak];
            if ([jailbreakCheck[@"isJailbroken"] boolValue]) {
                [self sendEventToJS:@"jailbreakDetected" withData:jailbreakCheck];
            }
            report[@"jailbreak"] = jailbreakCheck;
        }
        
        if (!self.enabledChecks || [self.enabledChecks[@"checkHookingFrameworks"] boolValue]) {
            NSDictionary* hookingCheck = [self checkHookingFrameworks];
            if ([hookingCheck[@"isHooked"] boolValue]) {
                [self sendEventToJS:@"fridaDetected" withData:hookingCheck];
            }
            report[@"hooking"] = hookingCheck;
        }
        
        if (!self.enabledChecks || [self.enabledChecks[@"checkDebugger"] boolValue]) {
            NSDictionary* debuggerCheck = [self checkDebugger];
            if ([debuggerCheck[@"isDebuggerAttached"] boolValue]) {
                [self sendEventToJS:@"debuggerDetected" withData:debuggerCheck];
            }
            report[@"debugger"] = debuggerCheck;
        }
        
        if (!self.enabledChecks || [self.enabledChecks[@"checkEmulator"] boolValue]) {
            NSDictionary* emulatorCheck = [self checkEmulator];
            if ([emulatorCheck[@"isEmulator"] boolValue]) {
                [self sendEventToJS:@"emulatorDetected" withData:emulatorCheck];
            }
            report[@"emulator"] = emulatorCheck;
        }
        
        if (!self.enabledChecks || [self.enabledChecks[@"checkAppIntegrity"] boolValue]) {
            NSDictionary* integrityCheck = [self checkAppIntegrity];
            if ([integrityCheck[@"isTampered"] boolValue]) {
                [self sendEventToJS:@"tamperDetected" withData:integrityCheck];
            }
            report[@"integrity"] = integrityCheck;
        }
        
    } @catch (NSException* exception) {
        NSLog(@"Error during monitoring checks: %@", exception);
    }
}

- (void)runRuntimeSentinelChecks {
    @try {
        NSDictionary* hookingCheck = [self checkHookingFrameworks];
        if ([hookingCheck[@"isHooked"] boolValue]) {
            [self sendEventToJS:@"fridaDetected" withData:hookingCheck];
        }

        NSDictionary* debuggerCheck = [self checkDebugger];
        if ([debuggerCheck[@"isDebuggerAttached"] boolValue]) {
            [self sendEventToJS:@"debuggerDetected" withData:debuggerCheck];
        }
    } @catch (NSException* exception) {
        NSLog(@"EnhancedIRoot runtime sentinel error: %@", exception);
    }
}

- (NSArray<NSString*>*)runtimeIntegritySelectorNames {
    return @[
        @"checkHookingFrameworks",
        @"checkFrida",
        @"checkFridaInternal",
        @"checkJailbreak",
        @"checkDebugger",
        @"checkAppIntegrity",
        @"getThreatReport:"
    ];
}

- (void)initializeRuntimeIntegrityBaselines {
    self.runtimeMethodIMPs = [NSMutableDictionary dictionary];
    self.runtimeMethodChecksums = [NSMutableDictionary dictionary];

    for (NSString* selectorName in [self runtimeIntegritySelectorNames]) {
        SEL selector = NSSelectorFromString(selectorName);
        Method method = class_getInstanceMethod([self class], selector);
        if (method == NULL) {
            continue;
        }

        IMP implementation = method_getImplementation(method);
        self.runtimeMethodIMPs[selectorName] = [NSValue valueWithPointer:implementation];

        NSData* checksum = [self checksumForImplementation:implementation length:64];
        if (checksum != nil) {
            self.runtimeMethodChecksums[selectorName] = checksum;
        }
    }
}

- (NSData*)checksumForImplementation:(IMP)implementation length:(NSUInteger)length {
    if (implementation == NULL || length == 0) {
        return nil;
    }

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256((const void*)implementation, (CC_LONG)length, hash);
    return [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
}

- (BOOL)checkRuntimeMethodIntegrity {
    if (self.runtimeMethodIMPs == nil || self.runtimeMethodChecksums == nil) {
        return NO;
    }

    for (NSString* selectorName in [self runtimeIntegritySelectorNames]) {
        SEL selector = NSSelectorFromString(selectorName);
        Method method = class_getInstanceMethod([self class], selector);
        if (method == NULL) {
            continue;
        }

        IMP currentImplementation = method_getImplementation(method);
        NSValue* originalValue = self.runtimeMethodIMPs[selectorName];
        if (originalValue != nil && [originalValue pointerValue] != currentImplementation) {
            return YES;
        }

        NSData* originalChecksum = self.runtimeMethodChecksums[selectorName];
        NSData* currentChecksum = [self checksumForImplementation:currentImplementation length:64];
        if (originalChecksum != nil && currentChecksum != nil && ![originalChecksum isEqualToData:currentChecksum]) {
            return YES;
        }
    }

    return NO;
}

- (BOOL)checkSuspiciousDyldImageCallback {
    return EnhancedIRootSuspiciousDyldImageSeen;
}

- (void)sendEventToJS:(NSString*)eventName withData:(NSDictionary*)data {
    NSString* js = [NSString stringWithFormat:@"cordova.fireDocumentEvent('%@', %@);",
                   eventName,
                   [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:data options:0 error:nil]
                                        encoding:NSUTF8StringEncoding]];
    
    [self.commandDelegate evalJs:js];
}

#pragma mark - Detection Methods

- (NSDictionary*)checkJailbreak {
    NSMutableDictionary* result = [NSMutableDictionary dictionary];
    NSMutableArray* detectedIssues = [NSMutableArray array];
    BOOL isJailbroken = NO;
    
    // Check for jailbreak paths
    for (NSString* path in self.jailbreakPaths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            isJailbroken = YES;
            [detectedIssues addObject:@"jailbreak_path_found"];
            break;
        }
    }
    
    // Check for jailbreak binaries
    for (NSString* binary in self.jailbreakBinaries) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:binary]) {
            isJailbroken = YES;
            [detectedIssues addObject:@"jailbreak_binary_found"];
            break;
        }
    }
    
    // Check for jailbreak schemes
    for (NSString* scheme in self.jailbreakSchemes) {
        if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:[scheme stringByAppendingString:@"://"]]]) {
            isJailbroken = YES;
            [detectedIssues addObject:@"jailbreak_scheme_found"];
            break;
        }
    }
    
    // Check for sandbox integrity
    if (![self checkSandboxIntegrity]) {
        isJailbroken = YES;
        [detectedIssues addObject:@"sandbox_integrity_compromised"];
    }
    
    // Check for suspicious environment variables
    if ([self checkSuspiciousEnvironmentVariables]) {
        isJailbroken = YES;
        [detectedIssues addObject:@"suspicious_environment_variables"];
    }
    
    result[@"isJailbroken"] = @(isJailbroken);
    result[@"detectedIssues"] = detectedIssues;
    return result;
}

- (NSDictionary*)checkHookingFrameworks {
    NSMutableDictionary* result = [NSMutableDictionary dictionary];
    NSMutableArray* detectedIssues = [NSMutableArray array];
    BOOL isHooked = NO;
    NSInteger riskScore = 0;
    
    // Check for suspicious libraries
    for (NSString* library in self.suspiciousLibraries) {
        if (dlopen([library UTF8String], RTLD_NOW)) {
            NSString* normalizedLibrary = [library lowercaseString];
            if ([normalizedLibrary containsString:@"frida"] || [normalizedLibrary containsString:@"gadget"]) {
                isHooked = YES;
                riskScore += 90;
                [detectedIssues addObject:@"frida_library_loaded"];
            } else {
                riskScore += 60;
                [detectedIssues addObject:@"suspicious_library_loaded"];
            }
            break;
        }
    }
    
    // Check for Frida
    if ([self checkFrida]) {
        isHooked = YES;
        riskScore += 90;
        [detectedIssues addObject:@"frida_detected"];
    }
    
    // Check loaded Mach-O images for runtime instrumentation artifacts.
    if ([self checkSuspiciousLoadedImages]) {
        isHooked = YES;
        riskScore += 90;
        [detectedIssues addObject:@"suspicious_loaded_image"];
    }

    // Check Mach thread names for Frida runtime workers.
    if ([self checkSuspiciousThreadNames]) {
        riskScore += 50;
        [detectedIssues addObject:@"suspicious_thread"];
    }

    // Check dyld callback state for instrumentation images loaded after startup.
    if ([self checkSuspiciousDyldImageCallback]) {
        isHooked = YES;
        riskScore += 90;
        [detectedIssues addObject:@"suspicious_dyld_image_added"];
    }

    // Check critical runtime methods for swizzling or inline patches.
    if ([self checkRuntimeMethodIntegrity]) {
        isHooked = YES;
        riskScore += 90;
        [detectedIssues addObject:@"runtime_integrity_violation"];
    }

    // Check for Objection
    if ([self checkObjection]) {
        riskScore += 50;
        [detectedIssues addObject:@"objection_detected"];
    }
    
    // Check for Cydia Substrate
    if ([self checkSubstrate]) {
        riskScore += 50;
        [detectedIssues addObject:@"substrate_detected"];
    }
    
    // Check for Frida default ports.
    if ([self checkFridaPorts]) {
        isHooked = YES;
        riskScore += 90;
        [detectedIssues addObject:@"frida_ports"];
    }

    // Check for other suspicious ports.
    if ([self checkSuspiciousPorts]) {
        riskScore += 50;
        [detectedIssues addObject:@"suspicious_ports"];
    }
    
    if (riskScore >= 70) {
        isHooked = YES;
    }

    result[@"isHooked"] = @(isHooked);
    result[@"riskScore"] = @(riskScore);
    if (EnhancedIRootSuspiciousDyldImageName[0] != '\0') {
        result[@"suspiciousDyldImage"] = @(EnhancedIRootSuspiciousDyldImageName);
    }
    result[@"detectedIssues"] = detectedIssues;
    return result;
}

- (NSDictionary*)checkDebugger {
    NSMutableDictionary* result = [NSMutableDictionary dictionary];
    NSMutableArray* detectedIssues = [NSMutableArray array];
    BOOL isDebuggerAttached = NO;
    
    // Check for debugger using sysctl
    if ([self checkDebuggerSysctl]) {
        isDebuggerAttached = YES;
        [detectedIssues addObject:@"debugger_sysctl"];
    }
    
    // Check for debugger using ptrace
    if ([self checkDebuggerPtrace]) {
        isDebuggerAttached = YES;
        [detectedIssues addObject:@"debugger_ptrace"];
    }
    
    // Check for debugger using timing
    if ([self checkDebuggerTiming]) {
        isDebuggerAttached = YES;
        [detectedIssues addObject:@"debugger_timing"];
    }
    
    result[@"isDebuggerAttached"] = @(isDebuggerAttached);
    result[@"detectedIssues"] = detectedIssues;
    return result;
}

- (NSDictionary*)checkAppIntegrity {
    NSMutableDictionary* result = [NSMutableDictionary dictionary];
    NSMutableArray* detectedIssues = [NSMutableArray array];
    BOOL isTampered = NO;
    
    // Check for code signature
    if (![self checkCodeSignature]) {
        isTampered = YES;
        [detectedIssues addObject:@"code_signature_invalid"];
    }
    
    // Check for suspicious modifications
    if ([self checkSuspiciousModifications]) {
        isTampered = YES;
        [detectedIssues addObject:@"suspicious_modifications"];
    }
    
    // Check for suspicious entitlements
    if ([self checkSuspiciousEntitlements]) {
        isTampered = YES;
        [detectedIssues addObject:@"suspicious_entitlements"];
    }    
  
    result[@"isTampered"] = @(isTampered);
    result[@"detectedIssues"] = detectedIssues;
    return result;
}

- (NSDictionary*)checkEmulator {
    NSMutableDictionary* result = [NSMutableDictionary dictionary];
    NSMutableArray* detectedIssues = [NSMutableArray array];
    BOOL isEmulator = NO;
    
    // Check for simulator environment
    #if TARGET_IPHONE_SIMULATOR
    isEmulator = YES;
    [detectedIssues addObject:@"simulator_environment"];
    #endif
    
    // Check for common emulator artifacts
    NSArray* emulatorPaths = @[
        @"/Applications/Xcode.app",
        @"/Applications/Xcode-beta.app",
        @"/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform",
        @"/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs"
    ];
    
    for (NSString* path in emulatorPaths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            isEmulator = YES;
            [detectedIssues addObject:@"emulator_artifacts_found"];
            break;
        }
    }
    
    // Check for simulator-specific environment variables
    if (getenv("SIMULATOR_DEVICE_NAME") != NULL ||
        getenv("SIMULATOR_RUNTIME_VERSION") != NULL ||
        getenv("SIMULATOR_DEVICE_FAMILY") != NULL) {
        isEmulator = YES;
        [detectedIssues addObject:@"simulator_environment_variables"];
    }
    
    // Check for simulator-specific hardware
    struct utsname systemInfo;
    uname(&systemInfo);
    NSString* deviceModel = @(systemInfo.machine);
    if ([deviceModel hasPrefix:@"x86_64"] || [deviceModel hasPrefix:@"i386"]) {
        isEmulator = YES;
        [detectedIssues addObject:@"simulator_hardware"];
    }
    
    result[@"isEmulator"] = @(isEmulator);
    result[@"detectedIssues"] = detectedIssues;
    return result;
}

#pragma mark - Helper Methods

- (BOOL)checkSandboxIntegrity {
    NSString* path = @"/private/var/mobile";
    struct stat stat_info;
    if (stat([path UTF8String], &stat_info) == 0) {
        return (stat_info.st_mode & S_IWOTH) == 0;
    }
    return YES;
}

- (BOOL)checkSuspiciousEnvironmentVariables {
    return getenv("DYLD_INSERT_LIBRARIES") != NULL;
}

- (BOOL)checkFrida {
    // Verify code integrity first
    if (![self verifyIntegrity]) {
        return YES; // Integrity check failed, assume tampering
    }
    
    // Add timing-based checks
    NSTimeInterval startTime = [NSDate date].timeIntervalSince1970;
    
    // Existing Frida checks...
    BOOL result = [self checkFridaInternal];
    
    NSTimeInterval endTime = [NSDate date].timeIntervalSince1970;
    NSTimeInterval duration = endTime - startTime;
    
    // If checks took too long, might indicate debugging
    if (duration > 0.1) { // 100ms
        return YES;
    }
    
    return result;
}

- (BOOL)checkFridaInternal {
    // Check for Frida environment variables
    if ([self checkFridaEnvironment]) {
        return YES;
    }
    
    // Check for Frida processes
    if ([self checkFridaProcesses]) {
        return YES;
    }
    
    // Check for Frida artifacts
    if ([self checkFridaArtifacts]) {
        return YES;
    }
    
    return NO;
}

- (BOOL)verifyIntegrity {
    // Check binary integrity
    if (![self verifyBinaryIntegrity]) {
        return NO;
    }
    
    // Check memory integrity
    if (![self verifyMemoryIntegrity]) {
        return NO;
    }
    
    // Check for suspicious behavior
    if ([self checkSuspiciousBehavior]) {
        return NO;
    }
    
    return YES;
}

- (BOOL)verifyBinaryIntegrity {
    NSData *currentChecksum = [self calculateIntegrityChecksum];
    return [currentChecksum isEqual:self.integrityChecksum];
}

- (BOOL)verifyMemoryIntegrity {
    // Check for suspicious memory patterns
    vm_size_t size;
    vm_address_t address = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name;
    
    while (vm_region_64(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_count, &object_name) == KERN_SUCCESS) {
        // Check for suspicious memory patterns
        if ((info.protection & VM_PROT_READ) && 
            (info.protection & VM_PROT_WRITE) && 
            (info.protection & VM_PROT_EXECUTE)) {
            return NO;
        }
        address += size;
    }
    
    return YES;
}

- (BOOL)checkSuspiciousBehavior {
    // Check for suspicious timing patterns
    if ([self checkTimingAnomalies]) {
        return YES;
    }
    
    // Check for suspicious system calls
    if ([self checkSuspiciousSyscalls]) {
        return YES;
    }
    
    // Check for suspicious file operations
    if ([self checkSuspiciousFileOps]) {
        return YES;
    }
    
    return NO;
}

- (BOOL)checkTimingAnomalies {
    NSTimeInterval start = [NSDate date].timeIntervalSince1970;
    [NSThread sleepForTimeInterval:0.001]; // 1ms
    NSTimeInterval end = [NSDate date].timeIntervalSince1970;
    
    // If sleep took significantly longer than expected, might indicate debugging
    return (end - start) > 0.002; // 2ms
}

- (BOOL)checkSuspiciousSyscalls {
    // Check for suspicious system calls using sysctl
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    
    if (sysctl(name, 4, &info, &info_size, NULL, 0) == 0) {
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }
    
    return NO;
}

- (BOOL)checkSuspiciousFileOps {
    // Check for suspicious file operations
    const char *paths[] = {
        "/usr/lib/dyld",
        "/usr/lib/libSystem.B.dylib",
        "/usr/lib/libobjc.A.dylib"
    };
    
    for (int i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        struct stat st;
        if (stat(paths[i], &st) == 0) {
            // Check file permissions
            if ((st.st_mode & S_IWOTH) != 0) {
                return YES;
            }
        }
    }
    
    return NO;
}

- (NSData *)calculateIntegrityChecksum {
    // Calculate SHA-256 checksum of the binary
    const char *path = [[[NSBundle mainBundle] executablePath] UTF8String];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return nil;
    
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    
    unsigned char buffer[4096];
    ssize_t bytes;
    while ((bytes = read(fd, buffer, sizeof(buffer))) > 0) {
        CC_SHA256_Update(&ctx, buffer, (CC_LONG)bytes);
    }
    
    close(fd);
    
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(hash, &ctx);
    
    return [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
}

- (void)checkIntegrity {
    NSData *currentChecksum = [self calculateIntegrityChecksum];
    if (![currentChecksum isEqual:self.integrityChecksum]) {
        // Integrity check failed, notify JavaScript
        [self sendEventToJS:@"integrityViolation" withData:@{@"reason": @"binary_modified"}];
    }
}

#pragma mark - Helper Methods

- (BOOL)checkSubstrate {
    return dlopen("/Library/MobileSubstrate/MobileSubstrate.dylib", RTLD_NOW) != NULL;
}

- (BOOL)checkSuspiciousPorts {
    NSArray* ports = @[@(22), @(23), @(4444), @(5555), @(6666), @(7777), @(8888), @(9999)];
    for (NSNumber* port in ports) {
        if ([self isPortOpen:[port intValue]]) {
            return YES;
        }
    }
    return NO;
}

- (NSArray<NSString*>*)runtimeInstrumentationTokens {
    return @[
        @"frida",
        @"gum-js",
        @"gumjs",
        @"gadget",
        @"frida-gadget",
        @"linjector",
        @"objection",
        @"cycript",
        @"substrate",
        @"substitute",
        @"ellekit",
        @"libhooker"
    ];
}

- (BOOL)checkSuspiciousLoadedImages {
    NSArray<NSString*>* tokens = [self runtimeInstrumentationTokens];
    uint32_t imageCount = _dyld_image_count();

    for (uint32_t i = 0; i < imageCount; i++) {
        const char* imageName = _dyld_get_image_name(i);
        if (imageName == NULL) {
            continue;
        }

        NSString* image = [@(imageName) lowercaseString];
        for (NSString* token in tokens) {
            if ([image containsString:token]) {
                return YES;
            }
        }
    }

    return NO;
}

- (BOOL)checkSuspiciousThreadNames {
    NSArray<NSString*>* tokens = @[
        @"frida",
        @"gum-js",
        @"gmain",
        @"gdbus",
        @"linjector",
        @"objection"
    ];
    thread_act_array_t threads;
    mach_msg_type_number_t threadCount = 0;

    if (task_threads(mach_task_self(), &threads, &threadCount) != KERN_SUCCESS) {
        return NO;
    }

    BOOL found = NO;
    for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
        pthread_t pthread = pthread_from_mach_thread_np(threads[i]);
        if (pthread == NULL) {
            continue;
        }

        char threadName[128] = {0};
        if (pthread_getname_np(pthread, threadName, sizeof(threadName)) != 0 || threadName[0] == '\0') {
            continue;
        }

        NSString* name = [@(threadName) lowercaseString];
        for (NSString* token in tokens) {
            if ([name containsString:token]) {
                found = YES;
                break;
            }
        }

        if (found) {
            break;
        }
    }

    vm_deallocate(mach_task_self(), (vm_address_t)threads, threadCount * sizeof(thread_t));
    return found;
}

- (BOOL)checkFridaPorts {
    for (NSNumber* port in @[@(27042), @(27043)]) {
        if ([self probeDbusPort:[port intValue]]) {
            return YES;
        }
    }
    return self.backgroundFridaDbusHit;
}

- (void)runBackgroundDbusPortScanOnce {
    @synchronized (self) {
        if (self.backgroundFridaScanStarted) {
            return;
        }
        self.backgroundFridaScanStarted = YES;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
        BOOL hit = [self scanDbusPortRangeParallelFrom:1024 to:65535];
        if (hit) {
            self.backgroundFridaDbusHit = YES;
        }
        dispatch_semaphore_signal(_fridaScanSemaphore);
    });
}

- (void)waitForBackgroundFridaScan:(NSTimeInterval)timeoutSeconds {
    if (self.backgroundFridaDbusHit) {
        return;
    }
    [self runBackgroundDbusPortScanOnce];
    dispatch_semaphore_wait(
        _fridaScanSemaphore,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeoutSeconds * NSEC_PER_SEC))
    );
}

- (BOOL)probeDbusPort:(int)port {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return NO;
    }

    struct timeval tv = {0, 40000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return NO;
    }

    const char authMessage[] = "\0AUTH\r\n";
    send(fd, authMessage, sizeof(authMessage) - 1, 0);

    char buffer[64];
    ssize_t bytesRead = recv(fd, buffer, sizeof(buffer), 0);
    close(fd);

    if (bytesRead <= 0) {
        return NO;
    }

    NSString* response = [[NSString alloc] initWithBytes:buffer length:(NSUInteger)bytesRead encoding:NSASCIIStringEncoding];
    return response != nil && [response containsString:@"REJECT"];
}

- (BOOL)scanDbusPortRangeParallelFrom:(int)startPort to:(int)endPort {
    if (startPort > endPort) {
        return NO;
    }

    static const int workerCount = 8;
    __block volatile BOOL scanFound = NO;
    int chunkSize = (endPort - startPort + 1 + workerCount - 1) / workerCount;
    if (chunkSize < 1) {
        chunkSize = 1;
    }

    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0);
    dispatch_group_t group = dispatch_group_create();

    for (int worker = 0; worker < workerCount; worker++) {
        int chunkStart = startPort + (worker * chunkSize);
        if (chunkStart > endPort) {
            break;
        }
        int chunkEnd = MIN(endPort, chunkStart + chunkSize - 1);

        dispatch_group_async(group, queue, ^{
            for (int port = chunkStart; port <= chunkEnd; port++) {
                if (scanFound) {
                    return;
                }
                if (port == 27042 || port == 27043) {
                    continue;
                }
                if ([self probeDbusPort:port]) {
                    scanFound = YES;
                    return;
                }
            }
        });
    }

    dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 12 * NSEC_PER_SEC));
    return scanFound;
}

- (BOOL)isPortOpen:(int)port {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NO;
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
    
    return result == 0;
}

- (BOOL)checkDebuggerSysctl {
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    
    if (sysctl(name, 4, &info, &info_size, NULL, 0) == 0) {
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }
    
    return NO;
}

- (BOOL)checkDebuggerPtrace {
    #if !(TARGET_IPHONE_SIMULATOR)
        // Use syscall instead of direct ptrace
        return syscall(SYS_ptrace, 31, 0, 0, 0) == -1;
    #else
        return NO;
    #endif
}

- (BOOL)checkDebuggerTiming {
    NSTimeInterval start = [NSDate date].timeIntervalSince1970;
    for (int i = 0; i < 1000; i++) {
        double result = sin(i); // Store the result to avoid warning
        (void)result; // Explicitly ignore the result
    }
    NSTimeInterval end = [NSDate date].timeIntervalSince1970;
    
    return (end - start) > 0.1;
}

- (BOOL)checkCodeSignature {
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSString *codeSignaturePath = [bundlePath stringByAppendingPathComponent:@"_CodeSignature"];
    NSString *infoPlistPath = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
    NSFileManager *fm = [NSFileManager defaultManager];

    return [fm fileExistsAtPath:codeSignaturePath] && [fm fileExistsAtPath:infoPlistPath];
}

- (BOOL)checkSuspiciousModifications {
    NSString* bundlePath = [[NSBundle mainBundle] bundlePath];
    NSArray* paths = @[
        [bundlePath stringByAppendingPathComponent:@"Info.plist"],
        [bundlePath stringByAppendingPathComponent:@"_CodeSignature"]
    ];
    
    for (NSString* path in paths) {
        if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
            return YES;
        }
    }
    
    return NO;
}

- (BOOL)checkSuspiciousEntitlements {
    // This method is no longer used in the new implementation
    return NO;
}

- (BOOL)checkFridaEnvironment {
    // Check for Frida-related environment variables
    const char* envVars[] = {
        "FRIDA_DNS_SERVER",
        "FRIDA_EXTRA_OPTIONS",
        "FRIDA_AGENT_SCRIPT",
        "FRIDA_AGENT_SCRIPT_BASE64",
        "FRIDA_AGENT_SCRIPT_PATH",
        "FRIDA_AGENT_SCRIPT_URL",
        "FRIDA_AGENT_SCRIPT_URL_BASE64",
        "FRIDA_AGENT_SCRIPT_URL_PATH",
        "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH",
        "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64",
        "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH",
        "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64",
        "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64_PATH",
        "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64",
        "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH",
        "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64",
        "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH",
        "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64",
        "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH",
        "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64"
    };
    
    for (int i = 0; i < sizeof(envVars) / sizeof(envVars[0]); i++) {
        if (getenv(envVars[i]) != NULL) {
            return YES;
        }
    }
    
    return NO;
}

- (BOOL)checkFridaProcesses {
    // Check for Frida-related processes
    const char* processes[] = {
        "frida-server",
        "frida-agent",
        "frida-gadget",
        "gum-js-loop",
        "gmain",
        "linjector"
    };
    
    for (int i = 0; i < sizeof(processes) / sizeof(processes[0]); i++) {
        if ([self isProcessRunning:processes[i]]) {
            return YES;
        }
    }
    
    return NO;
}

- (BOOL)checkFridaArtifacts {
    // Check for Frida-related files and directories
    const char* artifacts[] = {
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-agent",
        "/data/local/tmp/frida-gadget",
        "/data/local/tmp/gum-js-loop",
        "/data/local/tmp/gmain",
        "/data/local/tmp/linjector",
        "/data/local/tmp/frida",
        "/data/local/tmp/re.frida",
        "/data/local/tmp/frida-agent.so",
        "/data/local/tmp/frida-gadget.so",
        "/data/local/tmp/gum-js-loop.so",
        "/data/local/tmp/gmain.so",
        "/data/local/tmp/linjector.so",
        "/usr/sbin/frida-server",
        "/usr/bin/frida-server",
        "/usr/local/bin/frida-server",
        "/usr/lib/frida/frida-agent.dylib",
        "/usr/lib/frida/frida-gadget.dylib",
        "/var/jb/usr/sbin/frida-server",
        "/var/jb/usr/bin/frida-server",
        "/var/jb/usr/local/bin/frida-server",
        "/var/jb/usr/lib/frida/frida-agent.dylib",
        "/var/jb/usr/lib/frida/frida-gadget.dylib",
        "/private/var/root/frida-server",
        "/private/var/mobile/frida-server",
        "/private/var/tmp/frida-server",
        "/tmp/frida-server"
    };
    
    for (int i = 0; i < sizeof(artifacts) / sizeof(artifacts[0]); i++) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:@(artifacts[i])]) {
            return YES;
        }
    }
    
    return NO;
}

- (BOOL)isProcessRunning:(const char*)processName {
    // Method 1: Using sysctl to get process list
    if ([self isProcessRunningViaSysctl:processName]) {
        return YES;
    }
    
    return NO;
}

- (BOOL)isProcessRunningViaSysctl:(const char*)processName {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size;
    
    // Get the size of the process list
    if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0) {
        return NO;
    }
    
    // Allocate memory for the process list
    struct kinfo_proc *procList = malloc(size);
    if (procList == NULL) {
        return NO;
    }
    
    // Get the process list
    if (sysctl(mib, 4, procList, &size, NULL, 0) < 0) {
        free(procList);
        return NO;
    }
    
    // Calculate number of processes
    int procCount = (int)(size / sizeof(struct kinfo_proc));
    
    // Check each process
    for (int i = 0; i < procCount; i++) {
        if (strcmp(procList[i].kp_proc.p_comm, processName) == 0) {
            free(procList);
            return YES;
        }
    }
    
    free(procList);
    return NO;
}

#pragma mark - Objection Detection Methods

- (BOOL)checkObjection {
    // Check for Objection artifacts
    if ([self checkObjectionArtifacts]) {
        return YES;
    }
    
    // Check for Objection environment
    if ([self checkObjectionEnvironment]) {
        return YES;
    }
    
    // Check for Objection processes
    if ([self checkObjectionProcesses]) {
        return YES;
    }
    
    // Check for Objection network activity
    if ([self checkObjectionNetwork]) {
        return YES;
    }
    
    return NO;
}

- (BOOL)checkObjectionArtifacts {
    for (NSString* path in self.objectionArtifacts) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            return YES;
        }
    }
    return NO;
}

- (BOOL)checkObjectionEnvironment {
    // Check for Objection-related environment variables
    const char* envVars[] = {
        "OBJECTION_AGENT",
        "OBJECTION_AGENT_SCRIPT",
        "OBJECTION_AGENT_SCRIPT_BASE64",
        "OBJECTION_AGENT_SCRIPT_PATH",
        "OBJECTION_AGENT_SCRIPT_URL",
        "OBJECTION_AGENT_SCRIPT_URL_BASE64",
        "OBJECTION_AGENT_SCRIPT_URL_PATH",
        "OBJECTION_AGENT_SCRIPT_URL_BASE64_PATH"
    };
    
    for (int i = 0; i < sizeof(envVars) / sizeof(envVars[0]); i++) {
        if (getenv(envVars[i]) != NULL) {
            return YES;
        }
    }
    
    return NO;
}

- (BOOL)checkObjectionProcesses {
    // Check for Objection-related processes
    const char* processes[] = {
        "objection",
        "objection-agent",
        "objection-gadget",
        "objection-js-loop",
        "objection-main"
    };
    
    for (int i = 0; i < sizeof(processes) / sizeof(processes[0]); i++) {
        if ([self isProcessRunning:processes[i]]) {
            return YES;
        }
    }
    
    return NO;
}

- (BOOL)checkObjectionNetwork {
    // Check for Objection's default ports
    NSArray* objectionPorts = @[@(8888), @(8889), @(8890)];
    for (NSNumber* port in objectionPorts) {
        if ([self isPortOpen:[port intValue]]) {
            return YES;
        }
    }
    
    // Check for Objection's default host
    const char* objectionHosts[] = {
        "127.0.0.1",
        "localhost"
    };
    
    for (int i = 0; i < sizeof(objectionHosts) / sizeof(objectionHosts[0]); i++) {
        for (NSNumber* port in objectionPorts) {
            if ([self isHostReachable:objectionHosts[i] onPort:[port intValue]]) {
                return YES;
            }
        }
    }
    
    return NO;
}

- (BOOL)isHostReachable:(const char*)host onPort:(int)port {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NO;
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);
    
    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
    
    return result == 0;
}

@end 
