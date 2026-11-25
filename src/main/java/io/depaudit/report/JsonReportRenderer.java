package io.depaudit.report;

import io.depaudit.diff.MetadataChange;
import io.depaudit.verify.UpgradeVerifier;
import io.depaudit.verify.VerificationResult;

import java.io.PrintStream;
import java.util.List;

/**
 * Renders an {@link AuditResult} as JSON for CI systems and pull-request bots.
 *
 * <p>Hand-written rather than pulled in from a JSON library: the output shape is small and fixed,
 * and a review tool that adds a serialisation dependency to every consumer's build is a hard sell.
 * The escaping is the part that must be right, so it is done in one place ({@link #escape}).
 */
public final class JsonReportRenderer {

    public void render(AuditResult r, PrintStream out) {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("{\n");
        sb.append("  \"oldSource\": ").append(q(r.oldSource())).append(",\n");
        sb.append("  \"newSource\": ").append(q(r.newSource())).append(",\n");
        sb.append("  \"offline\": ").append(r.offline()).append(",\n");
        sb.append("  \"blocking\": ").append(r.isBlocking()).append(",\n");
        sb.append("  \"summary\": {\n");
        sb.append("    \"changes\": ").append(r.diff().changes().size()).append(",\n");
        sb.append("    \"upgrades\": ").append(r.diff().upgrades().size()).append(",\n");
        sb.append("    \"blockingChanges\": ").append(r.blockers().size()).append(",\n");
        sb.append("    \"contradictions\": ").append(r.contradictions().size()).append(",\n");
        sb.append("    \"unconfirmed\": ").append(r.unresolved().size()).append(",\n");
        sb.append("    \"routineUpgrades\": ").append(r.routineUpgrades()).append("\n");
        sb.append("  },\n");

        sb.append("  \"changes\": [\n");
        List<VerificationResult> vs = r.changeVerdicts();
        for (int i = 0; i < vs.size(); i++) {
            VerificationResult v = vs.get(i);
            MetadataChange c = v.change();
            sb.append("    {\n");
            sb.append("      \"kind\": ").append(q(c.kind().name())).append(",\n");
            sb.append("      \"category\": ").append(q(c.category().name())).append(",\n");
            sb.append("      \"severity\": ").append(q(c.severity().name())).append(",\n");
            sb.append("      \"subject\": ").append(q(c.subject())).append(",\n");
            sb.append("      \"artifact\": ").append(q(c.artifactName())).append(",\n");
            sb.append("      \"coordinates\": ").append(c.coordinates() == null
                    ? "null" : q(c.coordinates().gav())).append(",\n");
            sb.append("      \"oldLine\": ").append(c.oldLine()).append(",\n");
            sb.append("      \"newLine\": ").append(c.newLine()).append(",\n");
            sb.append("      \"verdict\": ").append(q(v.verdict().name())).append(",\n");
            sb.append("      \"tier\": ").append(v.tier() == null
                    ? "null" : q(v.tier().name())).append(",\n");
            sb.append("      \"detail\": ").append(detailJson(c)).append(",\n");
            sb.append("      \"evidence\": ").append(stringArray(v.evidence())).append("\n");
            sb.append("    }").append(i < vs.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"upgrades\": [\n");
        List<UpgradeVerifier.UpgradeVerification> us = r.upgradeVerdicts();
        for (int i = 0; i < us.size(); i++) {
            UpgradeVerifier.UpgradeVerification u = us.get(i);
            sb.append("    {\n");
            sb.append("      \"from\": ").append(q(u.upgrade().from().gav())).append(",\n");
            sb.append("      \"to\": ").append(q(u.upgrade().to().gav())).append(",\n");
            sb.append("      \"oldLine\": ").append(u.upgrade().oldLine()).append(",\n");
            sb.append("      \"newLine\": ").append(u.upgrade().newLine()).append(",\n");
            sb.append("      \"verdict\": ").append(q(u.verdict().name())).append(",\n");
            sb.append("      \"tier\": ").append(u.tier() == null
                    ? "null" : q(u.tier().name())).append(",\n");
            sb.append("      \"evidence\": ").append(stringArray(u.evidence())).append("\n");
            sb.append("    }").append(i < us.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");
        out.print(sb);
    }

    private static String detailJson(MetadataChange c) {
        if (c.detail() instanceof MetadataChange.Detail.DigestChange d) {
            return "{\"type\":\"digest\",\"algorithm\":" + q(d.algorithm())
                    + ",\"oldValue\":" + q(d.oldValue())
                    + ",\"newValue\":" + q(d.newValue())
                    + ",\"oldOrigin\":" + q(d.oldOrigin())
                    + ",\"newOrigin\":" + q(d.newOrigin())
                    + ",\"alsoTrust\":" + (d.newAlsoTrust() || d.oldAlsoTrust()) + "}";
        }
        if (c.detail() instanceof MetadataChange.Detail.PgpKeysChange p) {
            return "{\"type\":\"pgp\",\"added\":" + stringArray(p.added())
                    + ",\"removed\":" + stringArray(p.removed()) + "}";
        }
        if (c.detail() instanceof MetadataChange.Detail.TrustedKeyChange t) {
            return "{\"type\":\"trustedKey\",\"oldId\":" + q(t.oldId())
                    + ",\"newId\":" + q(t.newId())
                    + ",\"oldScope\":" + q(t.oldScope())
                    + ",\"newScope\":" + q(t.newScope())
                    + ",\"keyMaterialAdded\":" + t.keyMaterialAdded() + "}";
        }
        if (c.detail() instanceof MetadataChange.Detail.ToggleChange t) {
            return "{\"type\":\"toggle\",\"name\":" + q(t.name())
                    + ",\"oldValue\":" + t.oldValue() + ",\"newValue\":" + t.newValue() + "}";
        }
        if (c.detail() instanceof MetadataChange.Detail.ComponentLifecycle l) {
            return "{\"type\":\"component\",\"note\":" + q(l.note()) + "}";
        }
        if (c.detail() instanceof MetadataChange.Detail.Unmodelled u) {
            return "{\"type\":\"unmodelled\",\"description\":" + q(u.description()) + "}";
        }
        return "null";
    }

    private static String stringArray(List<String> items) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(q(items.get(i)));
        }
        return sb.append("]").toString();
    }

    /** Null-safe JSON string literal. */
    static String q(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (ch < 0x20) {
                        sb.append(String.format("\\u%04x", (int) ch));
                    } else {
                        sb.append(ch);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }
}
