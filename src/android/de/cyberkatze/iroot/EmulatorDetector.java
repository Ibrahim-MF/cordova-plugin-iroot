package de.cyberkatze.iroot;

import android.content.Context;
import android.os.Build;
import android.telephony.TelephonyManager;
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
import java.util.Set;

public class EmulatorDetector {
    private static final String TAG = "EmulatorDetector";
    private final Context context;
    private final Set<String> emulatorFiles;
    private final Set<String> emulatorProps;
    private final Set<String> genymotionFiles;
    private final Set<String> qemuFiles;

    public EmulatorDetector(Context context) {
        this.context = context;
        
        this.emulatorFiles = new HashSet<>(Arrays.asList(
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
            "/dev/socket/qemud",
            "/dev/qemu_pipe"
        ));

        this.emulatorProps = new HashSet<>(Arrays.asList(
            "init.svc.qemud",
            "init.svc.qemu-props",
            "qemu.hw.mainkeys",
            "qemu.settings.system.screen_off_timeout",
            "ro.bootloader",
            "ro.bootmode",
            "ro.hardware",
            "ro.kernel.android.qemud",
            "ro.kernel.qemu.gles",
            "ro.kernel.qemu"
        ));

        this.genymotionFiles = new HashSet<>(Arrays.asList(
            "/dev/socket/genyd",
            "/dev/socket/baseband_genyd"
        ));

        this.qemuFiles = new HashSet<>(Arrays.asList(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
            "/dev/socket/baseband_genyd"
        ));
    }

    public JSONObject check() throws JSONException {
        JSONObject result = new JSONObject();
        boolean isEmulator = false;
        List<String> detectedIssues = new ArrayList<>();

        // Check build properties
        if (checkBuildProps()) {
            isEmulator = true;
            detectedIssues.add("build_props_emulator");
        }

        // Check for emulator files
        if (checkEmulatorFiles()) {
            isEmulator = true;
            detectedIssues.add("emulator_files_found");
        }

        // Check for Genymotion
        if (checkGenymotion()) {
            isEmulator = true;
            detectedIssues.add("genymotion_detected");
        }

        // Check for QEMU
        if (checkQemu()) {
            isEmulator = true;
            detectedIssues.add("qemu_detected");
        }

        // Check hardware
        if (checkHardware()) {
            isEmulator = true;
            detectedIssues.add("emulator_hardware");
        }

        // Check telephony
        if (checkTelephony()) {
            isEmulator = true;
            detectedIssues.add("emulator_telephony");
        }

        result.put("isEmulator", isEmulator);
        result.put("detectedIssues", new JSONArray(detectedIssues));
        return result;
    }

    private boolean checkBuildProps() {
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

    private boolean checkEmulatorFiles() {
        for (String path : emulatorFiles) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkGenymotion() {
        for (String path : genymotionFiles) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkQemu() {
        for (String path : qemuFiles) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkHardware() {
        // Check for emulator-specific hardware
        return Build.HARDWARE.contains("goldfish")
            || Build.HARDWARE.contains("ranchu")
            || Build.HARDWARE.contains("vbox86")
            || Build.HARDWARE.contains("vbox86p")
            || Build.HARDWARE.contains("qemu");
    }

    private boolean checkTelephony() {
        TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (tm == null) return true;

        String networkOperatorName = tm.getNetworkOperatorName();
        return networkOperatorName == null
            || networkOperatorName.equals("Android")
            || networkOperatorName.equals("");
    }

    private boolean checkEmulatorProps() {
        for (String prop : emulatorProps) {
            String value = System.getProperty(prop);
            if (value != null && !value.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkEmulatorProcesses() {
        try {
            Process process = Runtime.getRuntime().exec("ps");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("qemu") || line.contains("goldfish")) {
                    return true;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error checking emulator processes: " + e.getMessage());
        }
        return false;
    }
} 