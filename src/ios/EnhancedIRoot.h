#import <Cordova/CDV.h>

@interface EnhancedIRoot : CDVPlugin

- (void)configure:(CDVInvokedUrlCommand*)command;
- (void)checkDeviceIntegrity:(CDVInvokedUrlCommand*)command;
- (void)checkRoot:(CDVInvokedUrlCommand*)command;
- (void)checkJailbreak:(CDVInvokedUrlCommand*)command;
- (void)checkHookingFrameworks:(CDVInvokedUrlCommand*)command;
- (void)checkDebugger:(CDVInvokedUrlCommand*)command;
- (void)checkEmulator:(CDVInvokedUrlCommand*)command;
- (void)checkAppIntegrity:(CDVInvokedUrlCommand*)command;
- (void)startMonitoring:(CDVInvokedUrlCommand*)command;
- (void)stopMonitoring:(CDVInvokedUrlCommand*)command;
- (void)getThreatReport:(CDVInvokedUrlCommand*)command;

@end 