package com.example.depreview.verify;

public record SignatureCheck(
        Status status,
        String keyId,
        String fingerprint,
        String signerUserId,
        String repositoryId,
        String artifactUrl,
        String message) {

    public enum Status {
        NOT_REQUESTED,
        NOT_CONFIGURED,
        NOT_FOUND,
        VALID_TRUSTED,
        VALID_UNTRUSTED,
        INVALID,
        ERROR,
        SKIPPED_OFFLINE
    }

    public boolean trusted() {
        return status == Status.VALID_TRUSTED;
    }
}
