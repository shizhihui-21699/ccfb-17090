package com.example.depreview.verify;

import java.util.List;

public record VerificationResult(
        Status status,
        String repositoryId,
        String artifactUrl,
        List<ChecksumCheck> checksumChecks,
        SignatureCheck signatureCheck,
        String message) {

    public enum Status {
        PUBLIC_MATCH,
        INTERNAL_MATCH,
        AUTHORIZED_REPOSITORY_MATCH,
        POLICY_HASH_MATCH,
        CHECKSUM_MISMATCH,
        NO_REPOSITORY_MATCH,
        INTERNAL_UNAVAILABLE,
        OFFLINE,
        SKIPPED,
        ERROR
    }

    public boolean verified() {
        return status == Status.PUBLIC_MATCH
                || status == Status.INTERNAL_MATCH
                || status == Status.AUTHORIZED_REPOSITORY_MATCH
                || status == Status.POLICY_HASH_MATCH;
    }
}
