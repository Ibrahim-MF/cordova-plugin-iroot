package de.cyberkatze.iroot;

import android.content.Context;
import android.content.pm.PackageManager;
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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class HookingFrameworkDetector {
    private static final String TAG = "HookingFrameworkDetector";
    private static final int RISK_THRESHOLD = 70;
    private static final int SCORE_HIGH_CONFIDENCE = 90;
    private static final int SCORE_MEDIUM_CONFIDENCE = 50;
    private final Context context;
    private final Set<String> fridaPackages;
    private final Set<String> xposedPackages;
    private final Set<String> fridaPaths;
    private final Set<String> xposedPaths;
    private final Set<Integer> fridaPorts;
    private final Set<String> objectionPaths;
    private final Set<String> objectionProcesses;
    private final Set<Integer> objectionPorts;

    private static final byte[] INTEGRITY_KEY = {
        (byte)0x7A, (byte)0x3B, (byte)0x9C, (byte)0x4D,
        (byte)0x2E, (byte)0x5F, (byte)0x8A, (byte)0x1B
    };

    public HookingFrameworkDetector(Context context) {
        this.context = context;
        
        // Frida packages
        this.fridaPackages = new HashSet<>(Arrays.asList(
            "com.sensepost.hiddentear",
            "com.sensepost.hiddentearpro",
            "com.sensepost.hiddentearpremium",
            "com.sensepost.hiddentearlite",
            "com.sensepost.hiddentearfree",
            "com.sensepost.hiddentearbasic",
            "com.sensepost.hiddentearstandard",
            "com.sensepost.hiddentearultimate",
            "com.sensepost.hiddentearprofessional",
            "com.sensepost.hiddentearenterprise",
            "re.frida.server",
            "re.frida.gadget",
            "com.frida.server",
            "com.frida.gadget"
        ));

        // Xposed packages
        this.xposedPackages = new HashSet<>(Arrays.asList(
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
            "io.github.lsposed.manager",
            "com.android.vending.billing.InAppBillingService.COIN",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.topjohnwu.magisk"
        ));

        // Frida paths
        this.fridaPaths = new HashSet<>(Arrays.asList(
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
            "/data/local/tmp/libfrida-gadget.so",
            "/data/local/tmp/libfrida-agent.so",
            "/data/local/tmp/libgum-js-loop.so"
        ));

        // Xposed paths
        this.xposedPaths = new HashSet<>(Arrays.asList(
            "/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so",
            "/system/xposed.prop",
            "/data/misc/xposed"
        ));

        // Frida ports
        this.fridaPorts = new HashSet<>(Arrays.asList(
            27042, 27043
        ));

        // Objection paths
        this.objectionPaths = new HashSet<>(Arrays.asList(
            "/data/local/tmp/objection",
            "/data/local/tmp/.objection",
            "/data/local/tmp/objection-agent",
            "/data/local/tmp/.objection-agent",
            "/data/local/tmp/objection-agent.js",
            "/data/local/tmp/.objection-agent.js",
            "/data/data/com.android.shell/objection",
            "/data/data/com.android.shell/.objection"
        ));

        // Objection processes
        this.objectionProcesses = new HashSet<>(Arrays.asList(
            "objection",
            "objection-agent",
            "objection-gadget",
            "objection-js-loop",
            "objection-main"
        ));

        // Objection ports
        this.objectionPorts = new HashSet<>(Arrays.asList(
            8888, 8889, 8890
        ));
    }

    public JSONObject check() throws JSONException {
        JSONObject result = new JSONObject();
        List<String> detectedIssues = new ArrayList<>();
        int riskScore = 0;

        if (checkFridaPackages()) {
            riskScore = addIssue(detectedIssues, "frida_package_found", riskScore, SCORE_HIGH_CONFIDENCE);
        }

        if (checkFridaArtifacts()) {
            riskScore = addIssue(detectedIssues, "frida_artifact_found", riskScore, SCORE_HIGH_CONFIDENCE);
        }

        if (checkFridaPorts()) {
            riskScore = addIssue(detectedIssues, "frida_ports", riskScore, SCORE_HIGH_CONFIDENCE);
        }

        if (checkFridaMemoryMaps()) {
            riskScore = addIssue(detectedIssues, "frida_library_loaded", riskScore, SCORE_HIGH_CONFIDENCE);
        }

        if (checkFridaThreadNames()) {
            riskScore = addIssue(detectedIssues, "frida_thread_found", riskScore, SCORE_HIGH_CONFIDENCE);
        }

        if (checkFridaUnixSockets()) {
            riskScore = addIssue(detectedIssues, "frida_socket_found", riskScore, SCORE_HIGH_CONFIDENCE);
        }

        if (checkXposed()) {
            riskScore = addIssue(detectedIssues, "xposed_detected", riskScore, SCORE_MEDIUM_CONFIDENCE);
        }

        if (checkObjection()) {
            riskScore = addIssue(detectedIssues, "objection_detected", riskScore, SCORE_MEDIUM_CONFIDENCE);
        }

        if (checkSuspiciousProcesses()) {
            riskScore = addIssue(detectedIssues, "suspicious_processes", riskScore, SCORE_MEDIUM_CONFIDENCE);
        }

        if (checkSuspiciousLibraries()) {
            riskScore = addIssue(detectedIssues, "suspicious_libraries", riskScore, SCORE_MEDIUM_CONFIDENCE);
        }

        if (checkSuspiciousMemoryRegions()) {
            riskScore = addIssue(detectedIssues, "suspicious_memory_regions", riskScore, SCORE_MEDIUM_CONFIDENCE);
        }

        result.put("isHooked", riskScore >= RISK_THRESHOLD);
        result.put("riskScore", riskScore);
        result.put("riskThreshold", RISK_THRESHOLD);
        result.put("detectedIssues", new JSONArray(detectedIssues));
        return result;
    }

    private int addIssue(List<String> detectedIssues, String issue, int currentScore, int issueScore) {
        if (!detectedIssues.contains(issue)) {
            detectedIssues.add(issue);
            return Math.min(100, currentScore + issueScore);
        }
        return currentScore;
    }

    private boolean verifyIntegrity() {
        try {
            // Get the current class's bytecode
            String className = this.getClass().getName().replace('.', '/');
            ClassLoader classLoader = this.getClass().getClassLoader();
            java.io.InputStream is = classLoader.getResourceAsStream(className + ".class");
            if (is == null) return false;

            // Calculate checksum
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                md.update(buffer, 0, read);
            }
            byte[] checksum = md.digest();

            // Verify against stored checksum
            return java.util.Arrays.equals(checksum, getStoredChecksum());
        } catch (Exception e) {
            return false;
        }
    }

    private byte[] getStoredChecksum() {
        // This would be replaced with the actual stored checksum
        return new byte[32];
    }

    private boolean checkNativeIntegrity() {
        try {
            System.loadLibrary("integrity");
            return nativeCheckIntegrity();
        } catch (UnsatisfiedLinkError e) {
            return false;
        }
    }

    private native boolean nativeCheckIntegrity();

    private boolean checkFridaPackages() {
        PackageManager pm = context.getPackageManager();
        for (String packageName : fridaPackages) {
            try {
                pm.getPackageInfo(packageName, PackageManager.GET_ACTIVITIES);
                Log.d(TAG, "Found Frida package: " + packageName);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // Package not found, continue checking
            }
        }
        return false;
    }

    private boolean checkFridaPorts() {
        return hasListeningPort("/proc/net/tcp", fridaPorts) || hasListeningPort("/proc/net/tcp6", fridaPorts);
    }

    private boolean checkFridaMemoryMaps() {
        return containsAny(readTextFile("/proc/self/maps"), Arrays.asList(
            "frida",
            "re.frida",
            "gum-js",
            "gumjs",
            "libgum",
            "gadget",
            "libfrida",
            "libfrida-gadget",
            "linjector"
        ));
    }

    private boolean checkFridaThreadNames() {
        File taskDir = new File("/proc/self/task");
        File[] taskFiles = taskDir.listFiles();
        if (taskFiles == null) {
            return false;
        }

        List<String> threadTokens = Arrays.asList(
            "frida",
            "gum-js-loop",
            "gumjs",
            "gmain",
            "gdbus",
            "linjector"
        );

        for (File taskFile : taskFiles) {
            String threadName = readTextFile(taskFile.getAbsolutePath() + "/comm");
            if (containsAny(threadName, threadTokens)) {
                Log.d(TAG, "Found Frida thread: " + threadName.trim());
                return true;
            }
        }
        return false;
    }

    private boolean checkFridaUnixSockets() {
        return containsAny(readTextFile("/proc/net/unix"), Arrays.asList(
            "frida",
            "re.frida",
            "frida-server",
            "frida-agent",
            "frida-gadget",
            "gum-js-loop",
            "linjector"
        ));
    }

    private boolean checkFrida() {
        return checkFridaPackages()
            || checkFridaArtifacts()
            || checkFridaPorts()
            || checkFridaMemoryMaps()
            || checkFridaThreadNames()
            || checkFridaUnixSockets()
            || checkFridaEnvironment()
            || checkFridaProcesses()
            || checkSuspiciousMemoryPatterns();
    }

    private boolean testPortConnection(int port) {
        try {
            java.net.Socket socket = new java.net.Socket();
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), 100);
            socket.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean hasListeningPort(String procNetPath, Set<Integer> ports) {
        String content = readTextFile(procNetPath);
        String[] lines = content.split("\\n");
        for (int port : ports) {
            String hexPort = String.format(Locale.US, ":%04X", port);
            for (String line : lines) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length > 3
                    && parts[1].toUpperCase(Locale.US).endsWith(hexPort)
                    && "0A".equals(parts[3])) {
                    Log.d(TAG, "Found listening port in " + procNetPath + ": " + port);
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

    private boolean containsAny(String content, List<String> tokens) {
        String lowerContent = content.toLowerCase(Locale.US);
        for (String token : tokens) {
            if (lowerContent.contains(token.toLowerCase(Locale.US))) {
                return true;
            }
        }
        return false;
    }

    private boolean checkMemoryMaps() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            Set<String> suspiciousPatterns = new HashSet<>(Arrays.asList(
                "frida", "gum-js", "gmain", "linjector", "re.frida", "gadget",
                "libfrida", "libgum", "libgadget", "liblinjector"
            ));
            
            while ((line = reader.readLine()) != null) {
                // Check for suspicious patterns
                for (String pattern : suspiciousPatterns) {
                    if (line.toLowerCase().contains(pattern.toLowerCase())) {
                        return true;
                    }
                }
                
                // Check for RWX memory regions
                if (line.contains("rwx")) {
                    // Additional analysis of RWX regions
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 2) {
                        String permissions = parts[1];
                        if (permissions.contains("rwx")) {
                            // Check if the region is suspiciously large
                            String[] addresses = parts[0].split("-");
                            if (addresses.length == 2) {
                                long start = Long.parseLong(addresses[0], 16);
                                long end = Long.parseLong(addresses[1], 16);
                                if ((end - start) > 0x1000) { // More than 4KB
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error checking memory maps: " + e.getMessage());
        }
        return false;
    }

    private boolean checkSuspiciousMemoryPatterns() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = reader.readLine()) != null) {
                // Check for suspicious memory patterns
                if (line.contains("rwx") || 
                    line.contains("r-xp") || 
                    line.contains("rw-p") || 
                    line.contains("r--p")) {
                    // Additional analysis of memory regions
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 6) {
                        String path = parts[5];
                        if (path.contains("frida") || 
                            path.contains("gum-js") || 
                            path.contains("gadget") || 
                            path.contains("linjector")) {
                            return true;
                        }
                    }
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error checking memory patterns: " + e.getMessage());
        }
        return false;
    }

    private boolean checkFridaEnvironment() {
        String[] envVars = {
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
            "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH",
            "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64",
            "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH",
            "FRIDA_AGENT_SCRIPT_URL_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64_PATH_BASE64"
        };

        for (String envVar : envVars) {
            if (System.getenv(envVar) != null) {
                return true;
            }
        }

        return false;
    }

    private boolean checkFridaProcesses() {
        try {
            Process process = Runtime.getRuntime().exec("ps");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                // Check for Frida-related processes
                if (line.contains("frida-server") ||
                    line.contains("frida-agent") ||
                    line.contains("frida-gadget") ||
                    line.contains("gum-js-loop") ||
                    line.contains("gmain") ||
                    line.contains("linjector")) {
                    return true;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error checking Frida processes: " + e.getMessage());
        }
        return false;
    }

    private boolean checkFridaArtifacts() {
        String[] artifacts = {
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

        for (String artifact : artifacts) {
            if (new File(artifact).exists()) {
                return true;
            }
        }

        return false;
    }

    private boolean checkXposed() {
        // Check for Xposed packages
        PackageManager pm = context.getPackageManager();
        for (String packageName : xposedPackages) {
            try {
                pm.getPackageInfo(packageName, PackageManager.GET_ACTIVITIES);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // Package not found, continue checking
            }
        }

        // Check for Xposed files
        for (String path : xposedPaths) {
            if (new File(path).exists()) {
                return true;
            }
        }

        // Check for Xposed in stack traces
        try {
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
            for (StackTraceElement element : stackTrace) {
                if (element.getClassName().contains("xposed") || 
                    element.getClassName().contains("XposedBridge")) {
                    return true;
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error checking stack traces: " + e.getMessage());
        }

        return false;
    }

    private boolean checkSuspiciousProcesses() {
        try {
            Process process = Runtime.getRuntime().exec("ps");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("frida") || 
                    line.contains("xposed") || 
                    line.contains("substrate") || 
                    line.contains("magisk") ||
                    line.contains("supersu")) {
                    return true;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error checking processes: " + e.getMessage());
        }
        return false;
    }

    private boolean checkSuspiciousLibraries() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("frida") || 
                    line.contains("xposed") || 
                    line.contains("substrate") || 
                    line.contains("magisk") ||
                    line.contains("supersu")) {
                    return true;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error checking libraries: " + e.getMessage());
        }
        return false;
    }

    private boolean checkSuspiciousMemoryRegions() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = reader.readLine()) != null) {
                // Check for RWX memory regions (common in hooking frameworks)
                if (line.contains("rwx")) {
                    return true;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error checking memory regions: " + e.getMessage());
        }
        return false;
    }

    private boolean checkSuspiciousBehavior() {
        // Check for suspicious timing patterns
        if (checkTimingAnomalies()) {
            return true;
        }

        // Check for suspicious system calls
        if (checkSuspiciousSyscalls()) {
            return true;
        }

        // Check for suspicious file operations
        if (checkSuspiciousFileOps()) {
            return true;
        }

        return false;
    }

    private boolean checkTimingAnomalies() {
        try {
            // Measure time for a simple operation
            long start = System.nanoTime();
            Thread.sleep(1);
            long end = System.nanoTime();
            
            // If sleep took significantly longer than expected, might indicate debugging
            return (end - start) > 2000000; // 2ms
        } catch (InterruptedException e) {
            return true;
        }
    }

    private boolean checkSuspiciousSyscalls() {
        try {
            // Check for suspicious system calls
            Process process = Runtime.getRuntime().exec("strace -p " + android.os.Process.myPid());
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("ptrace") || 
                    line.contains("fork") || 
                    line.contains("execve")) {
                    return true;
                }
            }
        } catch (IOException e) {
            // Ignore
        }
        return false;
    }

    private boolean checkSuspiciousFileOps() {
        try {
            // Check for suspicious file operations
            Process process = Runtime.getRuntime().exec("lsof -p " + android.os.Process.myPid());
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("frida") || 
                    line.contains("gadget") || 
                    line.contains("linjector")) {
                    return true;
                }
            }
        } catch (IOException e) {
            // Ignore
        }
        return false;
    }

    private boolean checkObjection() {
        // Check for Objection artifacts
        if (checkObjectionArtifacts()) {
            return true;
        }

        // Check for Objection processes
        if (checkObjectionProcesses()) {
            return true;
        }

        // Check for Objection network activity
        if (checkObjectionNetwork()) {
            return true;
        }

        // Check for Objection environment
        if (checkObjectionEnvironment()) {
            return true;
        }

        return false;
    }

    private boolean checkObjectionArtifacts() {
        for (String path : objectionPaths) {
            File file = new File(path);
            if (file.exists()) {
                Log.d(TAG, "Found Objection artifact: " + path);
                return true;
            }
        }
        return false;
    }

    private boolean checkObjectionProcesses() {
        try {
            Process process = Runtime.getRuntime().exec("ps -A");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                for (String objectionProcess : objectionProcesses) {
                    if (line.contains(objectionProcess)) {
                        Log.d(TAG, "Found Objection process: " + line);
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error checking Objection processes: " + e.getMessage());
        }
        return false;
    }

    private boolean checkObjectionNetwork() {
        for (int port : objectionPorts) {
            if (testPortConnection(port)) {
                Log.d(TAG, "Found Objection network activity on port: " + port);
                return true;
            }
        }
        return false;
    }

    private boolean checkObjectionEnvironment() {
        // Check for Objection-related environment variables
        String[] envVars = {
            "OBJECTION_AGENT",
            "OBJECTION_AGENT_SCRIPT",
            "OBJECTION_AGENT_SCRIPT_BASE64",
            "OBJECTION_AGENT_SCRIPT_PATH",
            "OBJECTION_AGENT_SCRIPT_URL",
            "OBJECTION_AGENT_SCRIPT_URL_BASE64",
            "OBJECTION_AGENT_SCRIPT_URL_PATH",
            "OBJECTION_AGENT_SCRIPT_URL_BASE64_PATH"
        };

        for (String envVar : envVars) {
            if (System.getenv(envVar) != null) {
                Log.d(TAG, "Found Objection environment variable: " + envVar);
                return true;
            }
        }

        // Check for Objection-related system properties
        String[] sysProps = {
            "objection.agent",
            "objection.agent.script",
            "objection.agent.script.base64",
            "objection.agent.script.path",
            "objection.agent.script.url",
            "objection.agent.script.url.base64",
            "objection.agent.script.url.path",
            "objection.agent.script.url.base64.path"
        };

        for (String prop : sysProps) {
            if (System.getProperty(prop) != null) {
                Log.d(TAG, "Found Objection system property: " + prop);
                return true;
            }
        }

        return false;
    }
}
