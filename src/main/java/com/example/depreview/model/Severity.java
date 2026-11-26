package com.example.depreview.model;

/** Severity used for merge-request gating. The ordinal order is intentional. */
public enum Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    public boolean atLeast(Severity threshold) {
        return this.ordinal() >= threshold.ordinal();
    }
}
