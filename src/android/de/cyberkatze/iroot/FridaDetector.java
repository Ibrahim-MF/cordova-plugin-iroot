package de.cyberkatze.iroot;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public final class FridaDetector {
    private static final String LOCALHOST = "127.0.0.1";
    private static final String PROC_TASK_PATH = "/proc/self/task";
    private static final String PROC_FD_PATH = "/proc/self/fd";

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

        if (scanDbusPorts()) {
            codes.add("HOOK_FRIDA_DBUS");
        }
        if (scanThreadNames()) {
            codes.add("HOOK_FRIDA_THREAD");
        }
        if (scanNamedPipes()) {
            codes.add("HOOK_FRIDA_PIPE");
        }

        try {
            String nativeCodes = nativeScan();
            if (nativeCodes != null && !nativeCodes.isEmpty()) {
                for (String code : nativeCodes.split(",")) {
                    if (!code.isEmpty()) {
                        codes.add(code);
                    }
                }
            }
        } catch (UnsatisfiedLinkError ignored) {
            // Native detector not available; keep Java vectors only.
        }

        return codes;
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

                name = name.trim().toLowerCase();
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

        for (File fd : fds) {
            try {
                String target = fd.getCanonicalPath().toLowerCase();
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

    private static boolean scanDbusPorts() {
        for (int port = 1024; port <= 65535; port++) {
            if (probeDbus(port)) {
                return true;
            }
        }
        return false;
    }

    private static boolean probeDbus(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(LOCALHOST, port), 20);
            socket.setSoTimeout(50);

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
