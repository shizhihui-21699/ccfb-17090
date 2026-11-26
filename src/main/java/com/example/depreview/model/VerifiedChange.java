package com.example.depreview.model;

public record VerifiedChange(
        String coordinate,
        String artifactName,
        String repositoryId,
        String verificationStatus,
        String signatureStatus) {
}
