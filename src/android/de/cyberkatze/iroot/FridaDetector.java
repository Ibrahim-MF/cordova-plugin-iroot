package de.cyberkatze.iroot;

import android.os.Build;
import android.os.Process;
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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class FridaDetector {
    private static final String LOCALHOST = "127.0.0.1";
    private static final String PROC_TASK_PATH = "/proc/self/task";
    private static final String PROC_FD_PATH = "/proc/self/fd";
    private static final int MAX_FD_SCAN = 512;
    private static final int[] FRIDA_DBUS_PORTS = {27042, 27043};
    private static final int BACKGROUND_THREADS = 8;
    private static final int BACKGROUND_DEFER_MS = 5000;
    private static final long BACKGROUND_WAIT_MS = 8000;

    private static volatile boolean backgroundDbusHit = false;
    private static volatile boolean backgroundScanStarted = false;
    private static volatile boolean scanImmediateRequested = false;
    private static final CountDownLatch backgroundScanLatch = new CountDownLatch(1);

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

    /**
     * Blocks up to {@link #BACKGROUND_WAIT_MS} for the one-time extended port scan.
     * Used by getSignals so the app needs only a single call.
     */
    public static void awaitBackgroundScan() {
        scanImmediateRequested = true;
        ensureBackgroundScanStarted();
        try {
            backgroundScanLatch.await(BACKGROUND_WAIT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

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

    private static boolean scanDbusPorts() {
        for (int port : FRIDA_DBUS_PORTS) {
            if (probeDbus(port, 20, 50)) {
                return true;
            }
        }
        if (backgroundDbusHit) {
            return true;
        }
        ensureBackgroundScanStarted();
        return false;
    }

    private static synchronized void ensureBackgroundScanStarted() {
        if (backgroundScanStarted) {
            return;
        }
        backgroundScanStarted = true;

        Thread scanThread = new Thread(() -> {
            Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
            try {
                for (int waited = 0; waited < BACKGROUND_DEFER_MS && !scanImmediateRequested; waited += 100) {
                    Thread.sleep(100);
                }
                if (!backgroundDbusHit) {
                    List<Integer> listeningPorts = collectListeningPorts(1024, 65535);
                    if (probeListeningPorts(listeningPorts)) {
                        backgroundDbusHit = true;
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                backgroundScanLatch.countDown();
            }
        }, "frida-dbus-scan");
        scanThread.setDaemon(true);
        scanThread.start();
    }

    private static List<Integer> collectListeningPorts(int minPort, int maxPort) {
        Set<Integer> ports = new HashSet<>();
        collectListeningPortsFrom("/proc/net/tcp", minPort, maxPort, ports);
        collectListeningPortsFrom("/proc/net/tcp6", minPort, maxPort, ports);
        ports.remove(27042);
        ports.remove(27043);
        return new ArrayList<>(ports);
    }

    private static void collectListeningPortsFrom(
            String procNetPath, int minPort, int maxPort, Set<Integer> out) {
        try (BufferedReader reader = new BufferedReader(new FileReader(procNetPath))) {
            reader.readLine();
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length <= 3 || !"0A".equals(parts[3])) {
                    continue;
                }
                String[] local = parts[1].split(":");
                if (local.length != 2) {
                    continue;
                }
                int port = Integer.parseInt(local[1], 16);
                if (port >= minPort && port <= maxPort) {
                    out.add(port);
                }
            }
        } catch (Exception ignored) {
            // No candidate list; extended scan becomes a no-op.
        }
    }

    private static boolean probeListeningPorts(List<Integer> ports) {
        if (ports.isEmpty()) {
            return false;
        }

        AtomicBoolean found = new AtomicBoolean(false);
        int threads = Math.min(BACKGROUND_THREADS, ports.size());
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        try {
            int chunkSize = Math.max(1, (ports.size() + threads - 1) / threads);
            List<Callable<Void>> tasks = new ArrayList<>(threads);

            for (int offset = 0; offset < ports.size(); offset += chunkSize) {
                final int start = offset;
                final int end = Math.min(ports.size(), offset + chunkSize);
                tasks.add(() -> {
                    for (int i = start; i < end && !found.get(); i++) {
                        if (probeDbus(ports.get(i), 30, 80)) {
                            found.set(true);
                        }
                    }
                    return null;
                });
            }

            executor.invokeAll(tasks, 8, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdownNow();
        }

        return found.get();
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

    private static boolean probeDbus(int port, int connectTimeoutMs, int readTimeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(LOCALHOST, port), connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs);

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
