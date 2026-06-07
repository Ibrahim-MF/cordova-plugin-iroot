package de.cyberkatze.iroot;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

public final class SignalCollector {
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
                add(signals, code, "ROOT", "hider");
            }
        } catch (Throwable t) {
            add(signals, "COLLECTION_ERROR", "TAMPER", t.getClass().getSimpleName());
        }

        return signals;
    }

    private static String categoryFor(String code) {
        if (code.startsWith("HOOK")) {
            return "HOOK";
        }
        if (code.startsWith("DEBUGGER")) {
            return "DEBUGGER";
        }
        if (code.startsWith("ROOT")) {
            return "ROOT";
        }
        return "HOOK";
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
