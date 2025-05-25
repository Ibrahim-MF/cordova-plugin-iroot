package de.cyberkatze.iroot;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.StatFs;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class DeviceIntegrityChecker {
    private static final String TAG = "DeviceIntegrityChecker";
    private final Context context;
    private final Set<String> rootPaths;
    private final Set<String> rootPackages;
    private final Set<String> dangerousProps;
    private final Set<String> systemPaths;

    public DeviceIntegrityChecker(Context context) {
        this.context = context;
        this.rootPaths = new HashSet<>(Arrays.asList(
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/su",
            "/system/xbin/mu"
        ));
        
        this.rootPackages = new HashSet<>(Arrays.asList(
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "eu.chainfire.supersu",
            "com.topjohnwu.magisk",
            "io.magisk",
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.formyhm.hideroot",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.zhiqupk.root.global",
            "com.alephzain.framaroot",
            "com.koushikdutta.rommanager",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.devadvance.rootcloak",
            "com.saurik.substrate"
        ));

        this.dangerousProps = new HashSet<>(Arrays.asList(
            "ro.debuggable",
            "ro.secure",
            "ro.build.type",
            "ro.build.tags",
            "ro.build.selinux",
            "service.adb.root",
            "persist.sys.usb.config"
        ));

        this.systemPaths = new HashSet<>(Arrays.asList(
            "/system",
            "/system/bin",
            "/system/sbin",
            "/system/xbin",
            "/vendor/bin",
            "/sbin",
            "/etc"
        ));
    }

    public JSONObject check() throws JSONException {
        JSONObject result = new JSONObject();
        result.put("isRooted", checkRoot().optBoolean("isRooted", false));
        result.put("isDebuggerConnected", checkDebugger());
        result.put("isEmulator", checkEmulator());
        result.put("isAdbEnabled", checkAdbEnabled());
        result.put("systemProperties", checkSystemProperties());
        result.put("systemPaths", checkSystemPaths());
        return result;
    }

    public JSONObject checkRoot() throws JSONException {
        JSONObject result = new JSONObject();
        boolean isRooted = false;
        List<String> detectedIssues = new ArrayList<>();

        // Check for su binary
        if (checkSuBinary()) {
            isRooted = true;
            detectedIssues.add("su_binary_found");
        }

        // Check for root management apps
        if (checkRootManagementApps()) {
            isRooted = true;
            detectedIssues.add("root_management_app_found");
        }

        // Check for Magisk
        if (checkMagisk()) {
            isRooted = true;
            detectedIssues.add("magisk_detected");
        }

        // Check for system properties
        if (checkDangerousProps()) {
            isRooted = true;
            detectedIssues.add("dangerous_props_found");
        }

        // Check for writable system paths
        if (checkWritableSystemPaths()) {
            isRooted = true;
            detectedIssues.add("writable_system_paths");
        }

        // Check for SELinux status
        if (checkSelinuxStatus()) {
            isRooted = true;
            detectedIssues.add("selinux_disabled");
        }

        result.put("isRooted", isRooted);
        result.put("detectedIssues", new JSONArray(detectedIssues));
        return result;
    }

    private boolean checkSuBinary() {
        for (String path : rootPaths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkRootManagementApps() {
        PackageManager pm = context.getPackageManager();
        for (String packageName : rootPackages) {
            try {
                pm.getPackageInfo(packageName, PackageManager.GET_ACTIVITIES);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // Package not found, continue checking
            }
        }
        return false;
    }

    private boolean checkMagisk() {
        // Check for Magisk paths
        String[] magiskPaths = {
            "/sbin/.magisk",
            "/sbin/magisk",
            "/data/adb/magisk",
            "/data/magisk"
        };

        for (String path : magiskPaths) {
            if (new File(path).exists()) {
                return true;
            }
        }

        // Check for Magisk in mount points
        try {
            Process process = Runtime.getRuntime().exec("mount");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("magisk")) {
                    return true;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error checking Magisk mount points: " + e.getMessage());
        }

        return false;
    }

    private boolean checkDangerousProps() {
        for (String prop : dangerousProps) {
            String value = System.getProperty(prop);
            if (value != null && (
                value.equals("1") ||
                value.equals("true") ||
                value.equals("userdebug") ||
                value.equals("test-keys")
            )) {
                return true;
            }
        }
        return false;
    }

    private boolean checkWritableSystemPaths() {
        for (String path : systemPaths) {
            File file = new File(path);
            if (file.exists() && file.canWrite()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkSelinuxStatus() {
        try {
            Process process = Runtime.getRuntime().exec("getenforce");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = reader.readLine();
            return line != null && line.equals("Permissive");
        } catch (IOException e) {
            Log.e(TAG, "Error checking SELinux status: " + e.getMessage());
            return false;
        }
    }

    private boolean checkDebugger() {
        return android.os.Debug.isDebuggerConnected();
    }

    private boolean checkEmulator() {
        return (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
            || Build.FINGERPRINT.startsWith("generic")
            || Build.FINGERPRINT.startsWith("unknown")
            || Build.HARDWARE.contains("goldfish")
            || Build.HARDWARE.contains("ranchu")
            || Build.MODEL.contains("google_sdk")
            || Build.MODEL.contains("Emulator")
            || Build.MODEL.contains("Android SDK built for x86")
            || Build.MANUFACTURER.contains("Genymotion")
            || Build.PRODUCT.contains("sdk_gphone")
            || Build.PRODUCT.contains("google_sdk")
            || Build.PRODUCT.contains("sdk")
            || Build.PRODUCT.contains("sdk_x86")
            || Build.PRODUCT.contains("vbox86p")
            || Build.PRODUCT.contains("emulator")
            || Build.PRODUCT.contains("simulator");
    }

    private boolean checkAdbEnabled() {
        return android.provider.Settings.Global.getInt(
            context.getContentResolver(),
            android.provider.Settings.Global.ADB_ENABLED,
            0
        ) == 1;
    }

    private JSONObject checkSystemProperties() throws JSONException {
        JSONObject props = new JSONObject();
        for (String prop : dangerousProps) {
            props.put(prop, System.getProperty(prop));
        }
        return props;
    }

    private JSONObject checkSystemPaths() throws JSONException {
        JSONObject paths = new JSONObject();
        for (String path : systemPaths) {
            File file = new File(path);
            JSONObject pathInfo = new JSONObject();
            pathInfo.put("exists", file.exists());
            pathInfo.put("canRead", file.canRead());
            pathInfo.put("canWrite", file.canWrite());
            pathInfo.put("canExecute", file.canExecute());
            paths.put(path, pathInfo);
        }
        return paths;
    }
} 