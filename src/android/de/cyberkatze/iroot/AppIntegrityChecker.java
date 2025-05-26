package de.cyberkatze.iroot;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AppIntegrityChecker {
    private static final String TAG = "AppIntegrityChecker";
    private final Context context;
    private final byte[] expectedSignature;

    public AppIntegrityChecker(Context context) {
        this.context = context;
        this.expectedSignature = getAppSignature();
    }

    public JSONObject check() throws JSONException {
        JSONObject result = new JSONObject();
        boolean isTampered = false;
        List<String> detectedIssues = new ArrayList<>();

        // Check app signature
        if (checkAppSignature()) {
            isTampered = true;
            detectedIssues.add("signature_mismatch");
        }

        // Check if app is debuggable
        if (checkDebuggable()) {
            isTampered = true;
            detectedIssues.add("app_debuggable");
        }

        // Check if app is running in debug mode
        if (checkDebugMode()) {
            isTampered = true;
            detectedIssues.add("debug_mode");
        }

        // Check for repackaging
        if (checkRepackaging()) {
            isTampered = true;
            detectedIssues.add("repackaging_detected");
        }

        // Check for suspicious modifications
        // if (checkSuspiciousModifications()) {
        //     isTampered = true;
        //     detectedIssues.add("suspicious_modifications");
        // }

        result.put("isTampered", isTampered);
        result.put("detectedIssues", new JSONArray(detectedIssues));
        return result;
    }

    private byte[] getAppSignature() {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                context.getPackageName(),
                PackageManager.GET_SIGNATURES
            );
            if (packageInfo != null && packageInfo.signatures != null && packageInfo.signatures.length > 0) {
                return packageInfo.signatures[0].toByteArray();
            }
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Error getting app signature: " + e.getMessage());
        }
        return null;
    }

    private boolean checkAppSignature() {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                context.getPackageName(),
                PackageManager.GET_SIGNATURES
            );
            if (packageInfo != null && packageInfo.signatures != null && packageInfo.signatures.length > 0) {
                byte[] currentSignature = packageInfo.signatures[0].toByteArray();
                return !Arrays.equals(currentSignature, expectedSignature);
            }
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Error checking app signature: " + e.getMessage());
        }
        return true;
    }

    private boolean checkDebuggable() {
        try {
            ApplicationInfo appInfo = context.getPackageManager().getApplicationInfo(
                context.getPackageName(),
                0
            );
            return (appInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Error checking debuggable flag: " + e.getMessage());
        }
        return false;
    }

    private boolean checkDebugMode() {
        return (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    private boolean checkRepackaging() {
        try {
            // Check if the app was installed from a trusted source
            String installerPackageName = context.getPackageManager().getInstallerPackageName(context.getPackageName());
            if (installerPackageName == null) {
                return true; // App was not installed through a package installer
            }

            // Check for common repackaging indicators
            if (installerPackageName.equals("com.android.vending")) {
                return false; // Installed from Play Store
            }

            // Check for suspicious installers
            String[] suspiciousInstallers = {
                "com.android.packageinstaller",
                "com.android.shell",
                "com.android.settings",
                "com.android.systemui"
            };

            for (String installer : suspiciousInstallers) {
                if (installerPackageName.equals(installer)) {
                    return true;
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Error checking repackaging: " + e.getMessage());
        }
        return false;
    }

    private boolean checkSuspiciousModifications() {
        try {
            // Check for suspicious file modifications
            String[] suspiciousPaths = {
                "/data/data/" + context.getPackageName() + "/lib",
                "/data/data/" + context.getPackageName() + "/files",
                "/data/data/" + context.getPackageName() + "/cache"
            };

            for (String path : suspiciousPaths) {
                File dir = new File(path);
                if (dir.exists() && dir.isDirectory()) {
                    File[] files = dir.listFiles();
                    if (files != null) {
                        for (File file : files) {
                            if (file.isFile() && file.canWrite()) {
                                return true;
                            }
                        }
                    }
                }
            }

            // Check for suspicious package modifications
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                context.getPackageName(),
                PackageManager.GET_ACTIVITIES | PackageManager.GET_SERVICES
            );

            if (packageInfo != null) {
                // Check if the app has been modified after installation
                long firstInstallTime = packageInfo.firstInstallTime;
                long lastUpdateTime = packageInfo.lastUpdateTime;
                if (lastUpdateTime > firstInstallTime) {
                    return true;
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Error checking suspicious modifications: " + e.getMessage());
        }
        return false;
    }

    private String calculateFileHash(String filePath) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            File file = new File(filePath);
            if (!file.exists()) return null;

            FileInputStream fis = new FileInputStream(file);
            byte[] byteArray = new byte[1024];
            int bytesCount;

            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }
            fis.close();

            byte[] bytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException | IOException e) {
            Log.e(TAG, "Error calculating file hash: " + e.getMessage());
        }
        return null;
    }
} 