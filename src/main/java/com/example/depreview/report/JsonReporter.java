package com.example.depreview.report;

import com.example.depreview.model.Finding;
import com.example.depreview.model.ReviewReport;
import com.example.depreview.model.VerifiedChange;
import com.example.depreview.verify.ChecksumCheck;
import com.example.depreview.verify.VerificationResult;

import java.util.List;
import java.util.Map;

public final class JsonReporter {

    public String render(ReviewReport report) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"verdict\": ").append(str(report.verdict())).append(",\n");
        json.append("  \"failed\": ").append(report.failed()).append(",\n");
        json.append("  \"threshold\": ").append(str(report.threshold().name())).append(",\n");
        json.append("  \"mutationCount\": ").append(report.mutationCount()).append(",\n");
        json.append("  \"verifiedUpgradeCount\": ").append(report.verifiedUpgradeCount()).append(",\n");
        json.append("  \"severityCounts\": ").append(counts(report.severityCounts())).append(",\n");
        json.append("  \"notices\": ").append(stringList(report.notices())).append(",\n");
        json.append("  \"verifiedChanges\": [");
        List<VerifiedChange> verified = report.verifiedChanges();
        for (int i = 0; i < verified.size(); i++) {
            VerifiedChange v = verified.get(i);
            json.append(i == 0 ? "\n" : ",\n");
            json.append("    {\"coordinate\": ").append(str(v.coordinate()))
                    .append(", \"artifactName\": ").append(str(v.artifactName()))
                    .append(", \"repositoryId\": ").append(str(v.repositoryId()))
                    .append(", \"verificationStatus\": ").append(str(v.verificationStatus()))
                    .append(", \"signatureStatus\": ").append(str(v.signatureStatus()))
                    .append('}');
        }
        if (!verified.isEmpty()) json.append('\n').append("  ");
        json.append("],\n");
        json.append("  \"findings\": [");
        List<Finding> findings = report.findings();
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            json.append(i == 0 ? "\n" : ",\n");
            appendFinding(json, f);
        }
        if (!findings.isEmpty()) json.append('\n').append("  ");
        json.append("]\n}\n");
        return json.toString();
    }

    private void appendFinding(StringBuilder json, Finding f) {
        json.append("    {\n");
        json.append("      \"id\": ").append(str(f.getId())).append(",\n");
        json.append("      \"severity\": ").append(str(f.getSeverity().name())).append(",\n");
        json.append("      \"title\": ").append(str(f.getTitle())).append(",\n");
        json.append("      \"file\": ").append(str(f.getFile())).append(",\n");
        json.append("      \"coordinate\": ").append(str(f.coordinateLabel())).append(",\n");
        json.append("      \"groupId\": ").append(str(f.getGroupId())).append(",\n");
        json.append("      \"artifactId\": ").append(str(f.getArtifactId())).append(",\n");
        json.append("      \"oldVersion\": ").append(str(f.getOldVersion())).append(",\n");
        json.append("      \"version\": ").append(str(f.getVersion())).append(",\n");
        json.append("      \"artifactName\": ").append(str(f.getArtifactName())).append(",\n");
        json.append("      \"kind\": ").append(str(f.getKind() == null ? null : f.getKind().name())).append(",\n");
        json.append("      \"changes\": ").append(stringList(f.getChanges())).append(",\n");
        json.append("      \"evidence\": ").append(stringList(f.getEvidenceLines())).append(",\n");
        json.append("      \"recommendation\": ").append(str(f.getRecommendation())).append(",\n");
        if (f.getBuildEvidence() != null) {
            json.append("      \"buildEvidence\": {\"provided\": ")
                    .append(f.getBuildEvidence().buildPatchProvided())
                    .append(", \"newVersionDeclared\": ")
                    .append(f.getBuildEvidence().newVersionDeclared())
                    .append(", \"oldVersionRemoved\": ")
                    .append(f.getBuildEvidence().oldVersionRemoved())
                    .append(", \"matchingLines\": ")
                    .append(stringList(f.getBuildEvidence().matchingLines()))
                    .append("},\n");
        }
        json.append("      \"verification\": ");
        appendVerification(json, f.getVerification());
        json.append('\n').append("    }");
    }

    private void appendVerification(StringBuilder json, VerificationResult v) {
        if (v == null) {
            json.append("null");
            return;
        }
        json.append("{\n");
        json.append("        \"status\": ").append(str(v.status().name())).append(",\n");
        json.append("        \"repositoryId\": ").append(str(v.repositoryId())).append(",\n");
        json.append("        \"artifactUrl\": ").append(str(v.artifactUrl())).append(",\n");
        json.append("        \"message\": ").append(str(v.message())).append(",\n");
        json.append("        \"checksums\": [");
        List<ChecksumCheck> checks = v.checksumChecks();
        for (int i = 0; i < checks.size(); i++) {
            ChecksumCheck c = checks.get(i);
            json.append(i == 0 ? "\n" : ",\n");
            json.append("          {\"algorithm\": ").append(str(c.algorithm()))
                    .append(", \"metadataValue\": ").append(str(c.metadataValue()))
                    .append(", \"remoteValue\": ").append(str(c.remoteValue()))
                    .append(", \"repositoryId\": ").append(str(c.repositoryId()))
                    .append(", \"found\": ").append(c.found())
                    .append(", \"matches\": ").append(c.matches())
                    .append('}');
        }
        if (!checks.isEmpty()) json.append('\n').append("        ");
        json.append("],\n");
        if (v.signatureCheck() == null) {
            json.append("        \"signature\": null\n");
        } else {
            var s = v.signatureCheck();
            json.append("        \"signature\": {\"status\": ").append(str(s.status().name()))
                    .append(", \"keyId\": ").append(str(s.keyId()))
                    .append(", \"fingerprint\": ").append(str(s.fingerprint()))
                    .append(", \"signerUserId\": ").append(str(s.signerUserId()))
                    .append(", \"message\": ").append(str(s.message()))
                    .append("}\n");
        }
        json.append("      }");
    }

    private static String counts(Map<com.example.depreview.model.Severity, Integer> counts) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (var entry : counts.entrySet()) {
            if (!first) sb.append(", ");
            sb.append('"').append(entry.getKey().name()).append("\": ").append(entry.getValue());
            first = false;
        }
        return sb.append('}').toString();
    }

    private static String stringList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return "[]";
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(str(values.get(i)));
        }
        return sb.append(']').toString();
    }

    private static String str(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }
}
