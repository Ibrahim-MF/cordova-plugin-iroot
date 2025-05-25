package de.cyberkatze.iroot;

import android.content.Context;
import android.os.Debug;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class DebuggerDetector {
    private static final String TAG = "DebuggerDetector";
    private final Context context;

    public DebuggerDetector(Context context) {
        this.context = context;
    }

    public JSONObject check() throws JSONException {
        JSONObject result = new JSONObject();
        boolean isDebuggerAttached = false;
        List<String> detectedIssues = new ArrayList<>();

        // Check for debugger using Android's Debug class
        if (checkDebuggerConnected()) {
            isDebuggerAttached = true;
            detectedIssues.add("debugger_connected");
        }

        // Check for debugger using TracerPid
        if (checkTracerPid()) {
            isDebuggerAttached = true;
            detectedIssues.add("tracer_pid_found");
        }

        // Check for JDWP thread
        if (checkJdwpThread()) {
            isDebuggerAttached = true;
            detectedIssues.add("jdwp_thread_found");
        }

        // Check for timing anomalies
        if (checkTimingAnomalies()) {
            isDebuggerAttached = true;
            detectedIssues.add("timing_anomalies");
        }

        // Check for debugger ports
        if (checkDebuggerPorts()) {
            isDebuggerAttached = true;
            detectedIssues.add("debugger_ports_found");
        }

        result.put("isDebuggerAttached", isDebuggerAttached);
        result.put("detectedIssues", new JSONArray(detectedIssues));
        return result;
    }

    private boolean checkDebuggerConnected() {
        return Debug.isDebuggerConnected();
    }

    private boolean checkTracerPid() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String tracerPid = line.substring(line.indexOf(":") + 1).trim();
                    return !tracerPid.equals("0");
                }
            }
            reader.close();
        } catch (IOException e) {
            Log.e(TAG, "Error checking TracerPid: " + e.getMessage());
        }
        return false;
    }

    private boolean checkJdwpThread() {
        try {
            Process process = Runtime.getRuntime().exec("ps");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("jdwp") || line.contains("debuggerd")) {
                    return true;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error checking JDWP thread: " + e.getMessage());
        }
        return false;
    }

    private boolean checkTimingAnomalies() {
        long startTime = System.nanoTime();
        try {
            // Perform some operations that should be fast
            for (int i = 0; i < 1000; i++) {
                Math.sin(i);
            }
        } catch (Exception e) {
            // Ignore exceptions
        }
        long endTime = System.nanoTime();
        long duration = endTime - startTime;

        // If the operation takes too long, it might indicate a debugger
        return duration > 1000000; // 1ms threshold
    }

    private boolean checkDebuggerPorts() {
        try {
            Process process = Runtime.getRuntime().exec("netstat -tuln");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                // Check for common debugger ports
                if (line.contains(":8600") || // Android Studio debugger
                    line.contains(":8601") || // Android Studio debugger
                    line.contains(":8602") || // Android Studio debugger
                    line.contains(":8700") || // Android Studio debugger
                    line.contains(":8701") || // Android Studio debugger
                    line.contains(":8702") || // Android Studio debugger
                    line.contains(":5037") || // ADB
                    line.contains(":8000") || // Common debug port
                    line.contains(":8001") || // Common debug port
                    line.contains(":8002")) { // Common debug port
                    return true;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error checking debugger ports: " + e.getMessage());
        }
        return false;
    }

    // Additional debugger detection methods

    private boolean checkDebuggerProperties() {
        try {
            String debuggerProperty = System.getProperty("java.vm.debug");
            return debuggerProperty != null && !debuggerProperty.isEmpty();
        } catch (Exception e) {
            Log.e(TAG, "Error checking debugger properties: " + e.getMessage());
            return false;
        }
    }

    private boolean checkDebuggerFiles() {
        String[] debuggerFiles = {
            "/data/local/tmp/gdb",
            "/data/local/tmp/gdb64",
            "/data/local/tmp/gdbserver",
            "/data/local/tmp/gdbserver64",
            "/data/local/tmp/android_server",
            "/data/local/tmp/android_server64"
        };

        for (String file : debuggerFiles) {
            if (new File(file).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkDebuggerEnvironment() {
        String[] debuggerEnvVars = {
            "ANDROID_DEBUGGABLE",
            "ANDROID_DEBUG_PORT",
            "ANDROID_DEBUG_SOCKET",
            "ANDROID_DEBUG_SOCKET_NAME",
            "ANDROID_DEBUG_SOCKET_PATH"
        };

        for (String envVar : debuggerEnvVars) {
            if (System.getenv(envVar) != null) {
                return true;
            }
        }
        return false;
    }
} 