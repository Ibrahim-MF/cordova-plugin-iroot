package de.cyberkatze.iroot;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

public final class SignalCollector {
    private static final String CATEGORY_HOOK = "HOOK";
    private static final String CATEGORY_DEBUGGER = "DEBUGGER";
    private static final String CATEGORY_ROOT = "ROOT";
    private static final String CATEGORY_EMULATOR = "EMULATOR";

    private SignalCollector() {
    }

    public static JSONArray collect() {
        JSONArray signals = new JSONArray();

        try {
            List<String> fridaCodes = FridaDetector.detect();
            for (String code : fridaCodes) {
                add(signals, code, categoryFor(code), "native");
            }

            List<String> rootHiderCodes = RootHiderDetector.detect();
            for (String code : rootHiderCodes) {
                add(signals, code, CATEGORY_ROOT, "hider");
            }

            List<String> emulatorCodes = EmulatorDetector.nativeDetect();
            for (String code : emulatorCodes) {
                add(signals, code, CATEGORY_EMULATOR, "native");
            }
        } catch (Throwable t) {
            add(signals, "COLLECTION_ERROR", "TAMPER", t.getClass().getSimpleName());
        }

        return signals;
    }

    private static String categoryFor(String code) {
        if (code.startsWith(CATEGORY_HOOK)) {
            return CATEGORY_HOOK;
        }
        if (code.startsWith(CATEGORY_DEBUGGER)) {
            return CATEGORY_DEBUGGER;
        }
        if (code.startsWith(CATEGORY_ROOT)) {
            return CATEGORY_ROOT;
        }
        if (code.startsWith(CATEGORY_EMULATOR)) {
            return CATEGORY_EMULATOR;
        }
        return CATEGORY_HOOK;
    }

    private static void add(JSONArray array, String code, String category, String evidence) {
        try {
            JSONObject obj = new JSONObject();
            obj.put("code", code);
            obj.put("category", category);
            obj.put("evidence", evidence);
            array.put(obj);
        } catch (Exception ignored) {
            // Ignore malformed signal payloads and continue collection.
        }
    }
}
