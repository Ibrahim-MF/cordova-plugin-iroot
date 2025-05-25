const exec = require('cordova/exec');

class EnhancedIRoot {
    constructor() {
        this.callbacks = {
            rootDetected: [],
            jailbreakDetected: [],
            fridaDetected: [],
            debuggerDetected: [],
            emulatorDetected: [],
            tamperDetected: []
        };
    }

    // Event handling
    on(eventName, callback) {
        if (this.callbacks[eventName]) {
            this.callbacks[eventName].push(callback);
        }
    }

    off(eventName, callback) {
        if (this.callbacks[eventName]) {
            this.callbacks[eventName] = this.callbacks[eventName].filter(cb => cb !== callback);
        }
    }

    // Configuration
    configure(options) {
        return new Promise((resolve, reject) => {
            exec(resolve, reject, 'EnhancedIRoot', 'configure', [options]);
        });
    }

    // Device Integrity & Compromise Detection
    checkDeviceIntegrity() {
        return new Promise((resolve, reject) => {
            exec(resolve, reject, 'EnhancedIRoot', 'checkDeviceIntegrity', []);
        });
    }

    // Root Detection (Android)
    checkRoot() {
        return new Promise((resolve, reject) => {
            exec(resolve, reject, 'EnhancedIRoot', 'checkRoot', []);
        });
    }

    // Jailbreak Detection (iOS)
    checkJailbreak() {
        return new Promise((resolve, reject) => {
            exec(resolve, reject, 'EnhancedIRoot', 'checkJailbreak', []);
        });
    }

    // Hooking Framework Detection
    checkHookingFrameworks() {
        return new Promise((resolve, reject) => {
            exec(resolve, reject, 'EnhancedIRoot', 'checkHookingFrameworks', []);
        });
    }

    // Debugger Detection
    checkDebugger() {
        return new Promise((resolve, reject) => {
            exec(resolve, reject, 'EnhancedIRoot', 'checkDebugger', []);
        });
    }

    // Emulator Detection
    checkEmulator() {
        return new Promise((resolve, reject) => {
            exec(resolve, reject, 'EnhancedIRoot', 'checkEmulator', []);
        });
    }

    // App Integrity
    checkAppIntegrity() {
        return new Promise((resolve, reject) => {
            exec(resolve, reject, 'EnhancedIRoot', 'checkAppIntegrity', []);
        });
    }

    // Start continuous monitoring
    startMonitoring(options = {}) {
        return new Promise((resolve, reject) => {
            exec(resolve, reject, 'EnhancedIRoot', 'startMonitoring', [options]);
        });
    }

    // Stop continuous monitoring
    stopMonitoring() {
        return new Promise((resolve, reject) => {
            exec(resolve, reject, 'EnhancedIRoot', 'stopMonitoring', []);
        });
    }

    // Get detailed threat report
    getThreatReport() {
        return new Promise((resolve, reject) => {
            exec(resolve, reject, 'EnhancedIRoot', 'getThreatReport', []);
        });
    }
}

// Create and export a singleton instance
const enhancedIRoot = new EnhancedIRoot();
module.exports = enhancedIRoot; 