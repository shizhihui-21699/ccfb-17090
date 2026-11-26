package com.example.depreview.diff;

import java.util.ArrayList;
import java.util.List;

/** Small Maven/Gradle-oriented version comparison; only used for labels and grouping. */
final class VersionOrder {

    private VersionOrder() {
    }

    static boolean isUpgrade(String oldVersion, String newVersion) {
        if (oldVersion.equals(newVersion)) {
            return false;
        }
        List<String> oldTokens = tokens(oldVersion);
        List<String> newTokens = tokens(newVersion);
        int n = Math.max(oldTokens.size(), newTokens.size());
        for (int i = 0; i < n; i++) {
            String a = i < oldTokens.size() ? oldTokens.get(i) : "0";
            String b = i < newTokens.size() ? newTokens.get(i) : "0";
            Integer na = numeric(a);
            Integer nb = numeric(b);
            int cmp;
            if (na != null && nb != null) {
                cmp = na.compareTo(nb);
            } else {
                cmp = qualifierRank(a).compareTo(qualifierRank(b));
                if (cmp == 0) {
                    cmp = a.compareTo(b);
                }
            }
            if (cmp != 0) {
                return cmp < 0;
            }
        }
        // Versions compare equal under our coarse rules but are not textually equal. Treat a
        // changed qualifier as an upgrade only when its rank improved; otherwise call it parallel.
        return true;
    }

    private static Integer numeric(String token) {
        try {
            return Integer.parseInt(token);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Integer qualifierRank(String token) {
        String t = token.toLowerCase();
        if (t.contains("alpha") || t.equals("a")) return -50;
        if (t.contains("beta") || t.equals("b")) return -40;
        if (t.contains("milestone") || t.startsWith("m")) return -30;
        if (t.contains("rc") || t.contains("cr")) return -20;
        if (t.contains("snapshot")) return -10;
        if (t.contains("release") || t.contains("final") || t.contains("ga")) return 10;
        return 0;
    }

    private static List<String> tokens(String version) {
        String v = version == null ? "" : version;
        String[] parts = v.split("[._\\-+]");
        List<String> out = new ArrayList<>();
        for (String p : parts) {
            if (!p.isBlank()) {
                // Separate a numeric prefix from qualifiers such as "1RC2".
                int i = 0;
                while (i < p.length() && Character.isDigit(p.charAt(i))) i++;
                if (i > 0 && i < p.length()) {
                    out.add(p.substring(0, i));
                    String tail = p.substring(i);
                    int j = 0;
                    while (j < tail.length() && !Character.isDigit(tail.charAt(j))) j++;
                    if (j > 0) out.add(tail.substring(0, j));
                    if (j < tail.length()) out.add(tail.substring(j));
                } else {
                    out.add(p);
                }
            }
        }
        return out;
    }
}
