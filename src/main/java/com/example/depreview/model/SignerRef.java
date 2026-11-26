package com.example.depreview.model;

public record SignerRef(String keyId, Integer line) {
    public SignerRef {
        keyId = keyId == null ? "" : keyId.trim().toUpperCase();
    }
}
