package de.cyberkatze.iroot;

import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class FridaDetector {
    private static final String LOCALHOST = "127.0.0.1";
    private static final String PROC_TASK_PATH = "/proc/self/task";
    private static final String PROC_FD_PATH = "/proc/self/fd";
    private static final int MAX_FD_SCAN = 512;
    private static final int DBUS_CONNECT_TIMEOUT_MS = 20;
    private static final int DBUS_READ_TIMEOUT_MS = 50;

    /**
     * Known frida-server D-Bus control ports. Probing only these (instead of the
     * full 1024-65535 range) keeps the scan in the millisecond range. Frida on a
     * non-default port and injected frida-gadget are still caught port-independently
     * via the native /proc/self/maps scan (HOOK_FRIDA_MAPS) in native_probe.c.
     */
    private static final int[] FRIDA_DBUS_PORTS = {27042, 27043};

    private FridaDetector() {
    }

    static {
        try {
            System.loadLibrary("native_probe");
        } catch (UnsatisfiedLinkError ignored) {
            // Native probe is optional at runtime; Java checks still run.
        }
    }

    public static native String nativeScan();

    public static List<String> detect() {
        List<String> codes = new ArrayList<>();

        // Native scan first — fast, hook-resistant, and authoritative for maps/debugger.
        appendNativeCodes(codes);

        if (scanThreadNames()) {
            codes.add("HOOK_FRIDA_THREAD");
        }
        if (scanNamedPipes()) {
            codes.add("HOOK_FRIDA_PIPE");
        }

        // Port probes are last and skipped when native already found Frida/debugger signals.
        if (!hasHookSignal(codes) && scanDbusPorts()) {
            codes.add("HOOK_FRIDA_DBUS");
        }

        return codes;
    }

    private static void appendNativeCodes(List<String> codes) {
        try {
            String nativeCodes = nativeScan();
            if (nativeCodes == null || nativeCodes.isEmpty()) {
                return;
            }

            for (String code : nativeCodes.split(",")) {
                if (!code.isEmpty() && !codes.contains(code)) {
                    codes.add(code);
                }
            }
        } catch (UnsatisfiedLinkError ignored) {
            // Native detector not available; keep Java vectors only.
        }
    }

    private static boolean hasHookSignal(List<String> codes) {
        for (String code : codes) {
            if (code.startsWith("HOOK_") || code.startsWith("DEBUGGER_")) {
                return true;
            }
        }
        return false;
    }

    private static boolean scanThreadNames() {
        File[] tasks = new File(PROC_TASK_PATH).listFiles();
        if (tasks == null) {
            return false;
        }

        for (File task : tasks) {
            File comm = new File(task, "comm");
            try (BufferedReader reader = new BufferedReader(new FileReader(comm))) {
                String name = reader.readLine();
                if (name == null) {
                    continue;
                }

                name = name.trim().toLowerCase(Locale.US);
                if (name.equals("gmain")
                        || name.equals("gdbus")
                        || name.equals("gum-js-loop")
                        || name.startsWith("pool-frida")) {
                    return true;
                }
            } catch (Exception ignored) {
                // Keep scanning other task comm files.
            }
        }

        return false;
    }

    private static boolean scanNamedPipes() {
        File[] fds = new File(PROC_FD_PATH).listFiles();
        if (fds == null) {
            return false;
        }

        int scanned = 0;
        for (File fd : fds) {
            if (scanned++ >= MAX_FD_SCAN) {
                break;
            }

            try {
                String target = readSymlinkTarget(fd).toLowerCase(Locale.US);
                if (target.contains("frida")
                        || target.contains("linjector")
                        || target.contains("gum")) {
                    return true;
                }
            } catch (Exception ignored) {
                // Keep scanning other file descriptors.
            }
        }
        return false;
    }

    private static String readSymlinkTarget(File link) throws ErrnoException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            return Os.readlink(link.getAbsolutePath());
        }

        try {
            return link.getCanonicalPath();
        } catch (Exception e) {
            return "";
        }
    }

    private static boolean scanDbusPorts() {
        for (int port : FRIDA_DBUS_PORTS) {
            if (probeDbus(port)) {
                return true;
            }
        }
        return false;
    }

    private static boolean probeDbus(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(LOCALHOST, port), DBUS_CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(DBUS_READ_TIMEOUT_MS);

            OutputStream os = socket.getOutputStream();
            InputStream is = socket.getInputStream();
            os.write("\0AUTH\r\n".getBytes());
            os.flush();

            byte[] buf = new byte[64];
            int n = is.read(buf);
            if (n > 0) {
                String response = new String(buf, 0, n);
                return response.contains("REJECT");
            }
        } catch (Exception ignored) {
            // Closed/filtered/non-DBus port.
        }
        return false;
    }
}
