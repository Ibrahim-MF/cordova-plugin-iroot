package de.cyberkatze.iroot;

import java.util.ArrayList;
import java.util.List;

public final class RootHiderDetector {
    private RootHiderDetector() {
    }

    static {
        try {
            System.loadLibrary("native_probe");
        } catch (UnsatisfiedLinkError ignored) {
            // Native probe is optional at runtime.
        }
    }

    private static native String nativeRootScan();

    public static List<String> detect() {
        List<String> codes = new ArrayList<>();
        try {
            String csv = nativeRootScan();
            if (csv != null && !csv.isEmpty()) {
                for (String code : csv.split(",")) {
                    if (!code.isEmpty()) {
                        codes.add(code);
                    }
                }
            }
        } catch (UnsatisfiedLinkError ignored) {
            // No-op: keep plugin behavior stable if native library is absent.
        }
        return codes;
    }
}
