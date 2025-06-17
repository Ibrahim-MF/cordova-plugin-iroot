package de.cyberkatze.iroot;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class EnhancedIRoot extends CordovaPlugin {
    private static final String TAG = "EnhancedIRoot";
    private ScheduledExecutorService monitoringExecutor;
    private Map<String, Boolean> enabledChecks;
    private Handler mainHandler;
    private DeviceIntegrityChecker deviceIntegrityChecker;
    private HookingFrameworkDetector hookingFrameworkDetector;
    private DebuggerDetector debuggerDetector;
    private EmulatorDetector emulatorDetector;
    private AppIntegrityChecker appIntegrityChecker;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        mainHandler = new Handler(Looper.getMainLooper());
        enabledChecks = new HashMap<>();
        initializeDetectors();
    }

    private void initializeDetectors() {
        Context context = cordova.getActivity().getApplicationContext();
        deviceIntegrityChecker = new DeviceIntegrityChecker(context);
        hookingFrameworkDetector = new HookingFrameworkDetector(context);
        debuggerDetector = new DebuggerDetector(context);
        emulatorDetector = new EmulatorDetector(context);
        appIntegrityChecker = new AppIntegrityChecker(context);
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        switch (action) {
            case "configure":
                configure(args.getJSONObject(0), callbackContext);
                return true;
            case "checkDeviceIntegrity":
                checkDeviceIntegrity(callbackContext);
                return true;
            case "checkRoot":
                checkRoot(callbackContext);
                return true;
            case "checkHookingFrameworks":
                checkHookingFrameworks(callbackContext);
                return true;
            case "checkDebugger":
                checkDebugger(callbackContext);
                return true;
            case "checkEmulator":
                checkEmulator(callbackContext);
                return true;
            case "checkAppIntegrity":
                checkAppIntegrity(callbackContext);
                return true;
            case "startMonitoring":
                startMonitoring(args.getJSONObject(0), callbackContext);
                return true;
            case "stopMonitoring":
                stopMonitoring(callbackContext);
                return true;
            case "getThreatReport":
                getThreatReport(callbackContext);
                return true;
            default:
                return false;
        }
    }

    private void configure(JSONObject options, CallbackContext callbackContext) {
        try {
            if (options.has("checkRoot")) enabledChecks.put("root", options.getBoolean("checkRoot"));
            if (options.has("checkHookingFrameworks")) enabledChecks.put("hooking", options.getBoolean("checkHookingFrameworks"));
            if (options.has("checkDebugger")) enabledChecks.put("debugger", options.getBoolean("checkDebugger"));
            if (options.has("checkEmulator")) enabledChecks.put("emulator", options.getBoolean("checkEmulator"));
            if (options.has("checkAppIntegrity")) enabledChecks.put("integrity", options.getBoolean("checkAppIntegrity"));
            
            callbackContext.success();
        } catch (JSONException e) {
            callbackContext.error("Invalid configuration options");
        }
    }

    private void checkDeviceIntegrity(CallbackContext callbackContext) {
        cordova.getThreadPool().execute(() -> {
            try {
                JSONObject result = deviceIntegrityChecker.check();
                callbackContext.success(result);
            } catch (Exception e) {
                callbackContext.error("Device integrity check failed: " + e.getMessage());
            }
        });
    }

    private void checkRoot(CallbackContext callbackContext) {
        cordova.getThreadPool().execute(() -> {
            try {
                JSONObject result = deviceIntegrityChecker.checkRoot();
                callbackContext.success(result);
            } catch (Exception e) {
                callbackContext.error("Root check failed: " + e.getMessage());
            }
        });
    }

    private void checkHookingFrameworks(CallbackContext callbackContext) {
        cordova.getThreadPool().execute(() -> {
            try {
                JSONObject result = hookingFrameworkDetector.check();
                callbackContext.success(result);
            } catch (Exception e) {
                callbackContext.error("Hooking framework check failed: " + e.getMessage());
            }
        });
    }

    private void checkDebugger(CallbackContext callbackContext) {
        cordova.getThreadPool().execute(() -> {
            try {
                JSONObject result = debuggerDetector.check();
                callbackContext.success(result);
            } catch (Exception e) {
                callbackContext.error("Debugger check failed: " + e.getMessage());
            }
        });
    }

    private void checkEmulator(CallbackContext callbackContext) {
        cordova.getThreadPool().execute(() -> {
            try {
                JSONObject result = emulatorDetector.check();
                callbackContext.success(result);
            } catch (Exception e) {
                callbackContext.error("Emulator check failed: " + e.getMessage());
            }
        });
    }

    private void checkAppIntegrity(CallbackContext callbackContext) {
        cordova.getThreadPool().execute(() -> {
            try {
                JSONObject result = appIntegrityChecker.check();
                callbackContext.success(result);
            } catch (Exception e) {
                callbackContext.error("App integrity check failed: " + e.getMessage());
            }
        });
    }

    private void startMonitoring(JSONObject options, CallbackContext callbackContext) {
        if (monitoringExecutor != null && !monitoringExecutor.isShutdown()) {
            callbackContext.error("Monitoring is already running");
            return;
        }

        try {
            int interval = options.optInt("interval", 5000); // Default 5 seconds
            monitoringExecutor = Executors.newSingleThreadScheduledExecutor();
            monitoringExecutor.scheduleAtFixedRate(this::runMonitoringChecks, 0, interval, TimeUnit.MILLISECONDS);
            callbackContext.success();
        } catch (Exception e) {
            callbackContext.error("Failed to start monitoring: " + e.getMessage());
        }
    }

    private void stopMonitoring(CallbackContext callbackContext) {
        if (monitoringExecutor != null) {
            monitoringExecutor.shutdown();
            monitoringExecutor = null;
        }
        if (callbackContext != null) {
            callbackContext.success();
        }
    }

    private void getThreatReport(CallbackContext callbackContext) {
        cordova.getThreadPool().execute(() -> {
            try {
                JSONObject report = new JSONObject();
                report.put("deviceIntegrity", deviceIntegrityChecker.check());
                report.put("hookingFrameworks", hookingFrameworkDetector.check());
                report.put("debugger", debuggerDetector.check());
                report.put("emulator", emulatorDetector.check());
                report.put("appIntegrity", appIntegrityChecker.check());
                callbackContext.success(report);
            } catch (Exception e) {
                callbackContext.error("Failed to generate threat report: " + e.getMessage());
            }
        });
    }

    private void runMonitoringChecks() {
        try {
            JSONObject report = new JSONObject();
            
            if (enabledChecks.getOrDefault("root", true)) {
                JSONObject rootCheck = deviceIntegrityChecker.checkRoot();
                if (rootCheck.optBoolean("isRooted", false)) {
                    sendEventToJS("rootDetected", rootCheck);
                }
                report.put("root", rootCheck);
            }

            if (enabledChecks.getOrDefault("hooking", true)) {
                JSONObject hookingCheck = hookingFrameworkDetector.check();
                if (hookingCheck.optBoolean("isHooked", false)) {
                    JSONArray issues = hookingCheck.optJSONArray("detectedIssues");
                    if (issues != null) {
                        for (int i = 0; i < issues.length(); i++) {
                            String issue = issues.getString(i);
                            if (issue.equals("frida_detected")) {
                                sendEventToJS("fridaDetected", hookingCheck);
                            } else if (issue.equals("objection_detected")) {
                                sendEventToJS("objectionDetected", hookingCheck);
                            }
                        }
                    }
                }
                report.put("hooking", hookingCheck);
            }

            if (enabledChecks.getOrDefault("debugger", true)) {
                JSONObject debuggerCheck = debuggerDetector.check();
                if (debuggerCheck.optBoolean("isDebuggerAttached", false)) {
                    sendEventToJS("debuggerDetected", debuggerCheck);
                }
                report.put("debugger", debuggerCheck);
            }

            if (enabledChecks.getOrDefault("emulator", true)) {
                JSONObject emulatorCheck = emulatorDetector.check();
                if (emulatorCheck.optBoolean("isEmulator", false)) {
                    sendEventToJS("emulatorDetected", emulatorCheck);
                }
                report.put("emulator", emulatorCheck);
            }

            if (enabledChecks.getOrDefault("integrity", true)) {
                JSONObject integrityCheck = appIntegrityChecker.check();
                if (integrityCheck.optBoolean("isTampered", false)) {
                    sendEventToJS("tamperDetected", integrityCheck);
                }
                report.put("integrity", integrityCheck);
            }

        } catch (Exception e) {
            Log.e(TAG, "Error during monitoring checks: " + e.getMessage());
        }
    }

    private void sendEventToJS(String eventName, JSONObject data) {
        String js = String.format("cordova.fireDocumentEvent('%s', %s);", eventName, data.toString());
        mainHandler.post(() -> webView.loadUrl("javascript:" + js));
    }

    @Override
    public void onDestroy() {
        stopMonitoring(null);
        super.onDestroy();
    }
} 