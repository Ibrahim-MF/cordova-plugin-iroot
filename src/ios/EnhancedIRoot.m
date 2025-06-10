#import "EnhancedIRoot.h"
#import <sys/stat.h>
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
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
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

@end

@implementation EnhancedIRoot

- (void)pluginInitialize {
    [super pluginInitialize];
    
    // Initialize integrity checksum
    self.integrityChecksum = [self calculateIntegrityChecksum];
    
    // Start periodic integrity checks
    self.integrityTimer = [NSTimer scheduledTimerWithTimeInterval:1.0
                                                         target:self
                                                       selector:@selector(checkIntegrity)
                                                       userInfo:nil
                                                        repeats:YES];
    
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
        @"/var/tmp/cydia.log"
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
    
    // Check for suspicious libraries
    for (NSString* library in self.suspiciousLibraries) {
        if (dlopen([library UTF8String], RTLD_NOW)) {
            isHooked = YES;
            [detectedIssues addObject:@"suspicious_library_loaded"];
            break;
        }
    }
    
    // Check for Frida
    if ([self checkFrida]) {
        isHooked = YES;
        [detectedIssues addObject:@"frida_detected"];
    }
    
    // Check for Objection
    if ([self checkObjection]) {
        isHooked = YES;
        [detectedIssues addObject:@"objection_detected"];
    }
    
    // Check for Cydia Substrate
    if ([self checkSubstrate]) {
        isHooked = YES;
        [detectedIssues addObject:@"substrate_detected"];
    }
    
    // Check for suspicious ports
    if ([self checkSuspiciousPorts]) {
        isHooked = YES;
        [detectedIssues addObject:@"suspicious_ports"];
    }
    
    result[@"isHooked"] = @(isHooked);
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
    // if (![self checkCodeSignature]) {
    //     isTampered = YES;
    //     [detectedIssues addObject:@"code_signature_invalid"];
    // }
    
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
    // Get the path to the app bundle
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    
    // Create a SecTrust object
    SecTrustRef trust = NULL;
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    
    // Get the app's certificate
    SecCertificateRef certificate = NULL;
    NSData *certificateData = [[NSData alloc] initWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"embedded.mobileprovision"]];
    
    if (certificateData) {
        certificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificateData);
    }
    
    if (certificate) {
        // Create an array of certificates
        CFArrayRef certificates = CFArrayCreate(NULL, (const void **)&certificate, 1, NULL);
        
        // Create the trust object
        OSStatus status = SecTrustCreateWithCertificates(certificates, policy, &trust);
        
        if (status == errSecSuccess) {
            // Evaluate the trust
            SecTrustResultType result;
            status = SecTrustEvaluate(trust, &result);
            
            // Clean up
            if (certificates) CFRelease(certificates);
            if (certificate) CFRelease(certificate);
            if (policy) CFRelease(policy);
            if (trust) CFRelease(trust);
            
            return (status == errSecSuccess && result == kSecTrustResultProceed);
        }
        
        // Clean up on failure
        if (certificates) CFRelease(certificates);
        if (certificate) CFRelease(certificate);
    }
    
    if (policy) CFRelease(policy);
    if (trust) CFRelease(trust);
    
    return NO;
}

- (BOOL)checkSuspiciousModifications {
    NSString* bundlePath = [[NSBundle mainBundle] bundlePath];
    NSArray* paths = @[
        [bundlePath stringByAppendingPathComponent:@"Info.plist"],
        [bundlePath stringByAppendingPathComponent:@"_CodeSignature"],
        [bundlePath stringByAppendingPathComponent:@"embedded.mobileprovision"]
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
        "/data/local/tmp/linjector.so"
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
