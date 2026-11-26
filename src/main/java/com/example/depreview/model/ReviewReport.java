package com.example.depreview.model;

import com.example.depreview.config.Gate;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public record ReviewReport(
        String verdict,
        Gate threshold,
        int mutationCount,
        int verifiedUpgradeCount,
        List<VerifiedChange> verifiedChanges,
        List<Finding> findings,
        List<String> notices) {

    public ReviewReport {
        findings = findings == null ? List.of() : List.copyOf(findings);
        verifiedChanges = verifiedChanges == null ? List.of() : List.copyOf(verifiedChanges);
        notices = notices == null ? List.of() : List.copyOf(notices);
    }

    public Map<Severity, Integer> severityCounts() {
        Map<Severity, Integer> counts = new TreeMap<>();
        for (Severity s : Severity.values()) {
            counts.put(s, 0);
        }
        findings.forEach(f -> counts.merge(f.getSeverity(), 1, Integer::sum));
        return counts;
    }

    public boolean failed() {
        if (threshold == Gate.NONE) {
            return false;
        }
        return findings.stream().anyMatch(f -> threshold.blocks(f.getSeverity()));
    }
}
