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
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class DebuggerDetector {
    private static final String TAG = "DebuggerDetector";
    private static final int RISK_THRESHOLD = 70;
    private static final int SCORE_HIGH_CONFIDENCE = 90;
    private static final int SCORE_MEDIUM_CONFIDENCE = 50;
    private final Context context;

    public DebuggerDetector(Context context) {
        this.context = context;
    }

    public JSONObject check() throws JSONException {
        JSONObject result = new JSONObject();
        List<String> detectedIssues = new ArrayList<>();
        int riskScore = 0;

        // Check for debugger using Android's Debug class
        if (checkDebuggerConnected()) {
            detectedIssues.add("debugger_connected");
            riskScore = addRisk(riskScore, SCORE_HIGH_CONFIDENCE);
        }

        // Check for debugger using TracerPid
        if (checkTracerPid()) {
            detectedIssues.add("tracer_pid_found");
            riskScore = addRisk(riskScore, SCORE_HIGH_CONFIDENCE);
        }

        // Check for JDWP thread
        if (checkJdwpThread()) {
            detectedIssues.add("jdwp_thread_found");
            riskScore = addRisk(riskScore, SCORE_MEDIUM_CONFIDENCE);
        }

        // Check for timing anomalies
        if (checkTimingAnomalies()) {
            detectedIssues.add("timing_anomalies");
            riskScore = addRisk(riskScore, SCORE_MEDIUM_CONFIDENCE);
        }

        // Check for debugger ports
        if (checkDebuggerPorts()) {
            detectedIssues.add("debugger_ports_found");
            riskScore = addRisk(riskScore, SCORE_MEDIUM_CONFIDENCE);
        }

        result.put("isDebuggerAttached", riskScore >= RISK_THRESHOLD);
        result.put("riskScore", riskScore);
        result.put("riskThreshold", RISK_THRESHOLD);
        result.put("detectedIssues", new JSONArray(detectedIssues));
        return result;
    }

    private int addRisk(int currentScore, int issueScore) {
        return Math.min(100, currentScore + issueScore);
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
        List<Integer> debuggerPorts = Arrays.asList(8600, 8601, 8602, 8700, 8701, 8702, 5037, 8000, 8001, 8002);
        return hasListeningPort("/proc/net/tcp", debuggerPorts) || hasListeningPort("/proc/net/tcp6", debuggerPorts);
    }

    private boolean hasListeningPort(String procNetPath, List<Integer> ports) {
        String[] lines = readTextFile(procNetPath).split("\\n");
        for (int port : ports) {
            String hexPort = String.format(Locale.US, ":%04X", port);
            for (String line : lines) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length > 3
                    && parts[1].toUpperCase(Locale.US).endsWith(hexPort)
                    && "0A".equals(parts[3])) {
                    Log.d(TAG, "Found debugger port in " + procNetPath + ": " + port);
                    return true;
                }
            }
        }
        return false;
    }

    private String readTextFile(String path) {
        StringBuilder content = new StringBuilder();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(path));
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append('\n');
            }
            reader.close();
        } catch (IOException e) {
            Log.e(TAG, "Error reading " + path + ": " + e.getMessage());
        }
        return content.toString();
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
