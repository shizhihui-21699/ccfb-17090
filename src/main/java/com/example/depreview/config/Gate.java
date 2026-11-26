package com.example.depreview.config;

import com.example.depreview.model.Severity;

public enum Gate {
    INFO(Severity.INFO),
    LOW(Severity.LOW),
    MEDIUM(Severity.MEDIUM),
    HIGH(Severity.HIGH),
    CRITICAL(Severity.CRITICAL),
    NONE(null);

    private final Severity severity;

    Gate(Severity severity) {
        this.severity = severity;
    }

    public Severity severity() {
        return severity;
    }

    public boolean blocks(Severity finding) {
        return severity != null && finding.atLeast(severity);
    }
}
