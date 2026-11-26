package com.example.depreview.verify;

import com.example.depreview.config.ArtifactPolicy;
import com.example.depreview.config.RepositoryConfig;
import com.example.depreview.config.ReviewConfig;
import com.example.depreview.model.HashValue;
import com.example.depreview.model.MetadataRecord;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public final class VerificationService {

    private final ReviewConfig config;
    private final Set<String> extraTrustedFingerprints;
    private final Map<String, RepositoryTransport> transports = new HashMap<>();
    private final GpgSignatureVerifier signatureVerifier;
    private final Path workRoot;

    public VerificationService(ReviewConfig config, Set<String> extraTrustedFingerprints) {
        this(config, extraTrustedFingerprints, new HashMap<>(), null, new GpgSignatureVerifier());
        for (RepositoryConfig repository : config.repositories()) {
            this.transports.put(repository.id(),
                    RepositoryTransportFactory.create(repository, config.timeoutSeconds()));
        }
    }

    VerificationService(
            ReviewConfig config,
            Set<String> extraTrustedFingerprints,
            Map<String, RepositoryTransport> transports,
            Path workRoot,
            GpgSignatureVerifier signatureVerifier) {
        this.config = config;
        this.extraTrustedFingerprints = extraTrustedFingerprints == null
                ? Set.of() : Set.copyOf(extraTrustedFingerprints);
        this.transports.putAll(transports == null ? Map.of() : transports);
        this.signatureVerifier = signatureVerifier == null ? new GpgSignatureVerifier() : signatureVerifier;
        this.workRoot = workRoot;
    }

    public VerificationResult verify(MetadataRecord record) {
        if (record == null || record.artifactName().isBlank()) {
            return new VerificationResult(VerificationResult.Status.SKIPPED, null, null,
                    List.of(), notRequested(), "Record has no artifact name");
        }
        if (!config.online()) {
            return new VerificationResult(VerificationResult.Status.OFFLINE, null, null,
                    List.of(),
                    new SignatureCheck(SignatureCheck.Status.SKIPPED_OFFLINE, null, null,
                            null, null, null, "Offline mode"),
                    "Network verification disabled");
        }

        ArtifactPolicy policy = config.policyFor(
                record.coordinates().groupId(), record.coordinates().artifactId()).orElse(null);
        if (policy != null) {
            for (HashValue hash : record.allHashes().toList()) {
                if (policy.approvedHashes().contains(hash.value())) {
                    return new VerificationResult(VerificationResult.Status.POLICY_HASH_MATCH,
                            "policy", null, List.of(), notRequested(),
                            "Hash is explicitly approved by policy: " + policy.reason());
                }
            }
        }

        String relativePath = record.coordinates().mavenPath() + "/" + record.artifactName();
        List<RepositoryConfig> candidates = candidates(policy, record.coordinates().groupId());
        List<ChecksumCheck> allChecks = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        boolean anyMismatch = false;
        boolean anyRepositoryError = false;

        for (RepositoryConfig repository : candidates) {
            RepositoryTransport transport = transports.get(repository.id());
            if (transport == null) {
                transport = RepositoryTransportFactory.create(repository, config.timeoutSeconds());
                transports.put(repository.id(), transport);
            }

            Attempt attempt;
            try {
                attempt = verifyAgainstRepository(record, relativePath, repository, transport);
            } catch (Exception e) {
                anyRepositoryError = true;
                errors.add(repository.id() + ": " + e.getMessage());
                continue;
            }
            allChecks.addAll(attempt.checks());
            if (attempt.match()) {
                Set<String> trusted = new LinkedHashSet<>(config.trustedFingerprints());
                trusted.addAll(extraTrustedFingerprints);
                if (policy != null) {
                    trusted.addAll(policy.trustedFingerprints());
                }
                SignatureCheck signature = maybeVerifySignature(
                        record, relativePath, repository, transport, trusted, policy);

                VerificationResult.Status status;
                if (repository.publicRepository()) {
                    status = VerificationResult.Status.PUBLIC_MATCH;
                } else if (repository.internal()) {
                    status = VerificationResult.Status.INTERNAL_MATCH;
                } else if (policy != null && policy.allowRepositorySpecificArtifact()) {
                    status = VerificationResult.Status.AUTHORIZED_REPOSITORY_MATCH;
                } else {
                    status = VerificationResult.Status.AUTHORIZED_REPOSITORY_MATCH;
                }
                return new VerificationResult(status, repository.id(),
                        repository.baseUrl().resolve(relativePath).toString(),
                        allChecks, signature,
                        "Checksum matches " + repository.id());
            }
            if (attempt.mismatch()) {
                anyMismatch = true;
            }
            errors.addAll(attempt.errors());
        }

        VerificationResult.Status status;
        String message;
        if (anyMismatch) {
            status = VerificationResult.Status.CHECKSUM_MISMATCH;
            message = "One or more repository checksums do not match the metadata";
        } else if (config.isInternalCoordinate(record.coordinates().groupId()) && anyRepositoryError) {
            status = VerificationResult.Status.INTERNAL_UNAVAILABLE;
            message = "Internal repository could not be reached; manual verification required";
        } else if (anyRepositoryError) {
            status = VerificationResult.Status.ERROR;
            message = "Repository verification failed: " + String.join("; ", errors);
        } else {
            status = VerificationResult.Status.NO_REPOSITORY_MATCH;
            message = "No configured repository published a matching checksum";
        }
        return new VerificationResult(status, null, null, allChecks, notRequested(), message);
    }

    private List<RepositoryConfig> candidates(ArtifactPolicy policy, String groupId) {
        List<RepositoryConfig> repositories = new ArrayList<>(config.repositories());
        if (policy != null && !policy.allowedRepositoryIds().isEmpty()) {
            repositories.removeIf(r -> !policy.allowedRepositoryIds().contains(r.id()));
        }
        boolean internal = config.isInternalCoordinate(groupId);
        repositories.sort((a, b) -> {
            int ai = (internal && a.internal()) ? 0 : a.publicRepository() ? 1 : 2;
            int bi = (internal && b.internal()) ? 0 : b.publicRepository() ? 1 : 2;
            return Integer.compare(ai, bi);
        });
        return repositories;
    }

    private Attempt verifyAgainstRepository(
            MetadataRecord record,
            String relativePath,
            RepositoryConfig repository,
            RepositoryTransport transport) throws Exception {

        List<ChecksumCheck> checks = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        Path downloadedArtifact = null;
        boolean mismatch = false;
        boolean strongMatch = false;
        boolean anyMatch = false;

        for (Map.Entry<String, List<HashValue>> entry : record.hashes().entrySet()) {
            String algorithm = entry.getKey();
            Set<String> trustedValues = new LinkedHashSet<>();
            entry.getValue().forEach(hash -> trustedValues.addAll(hash.trustedValues()));
            String expected = String.join(" OR ", trustedValues);
            String checksumPath = relativePath + "." + algorithm;
            Optional<String> sidecar = transport.getString(checksumPath);
            if (sidecar.isPresent()) {
                String remote = firstHexToken(sidecar.get());
                boolean matches = trustedValues.contains(remote);
                checks.add(new ChecksumCheck(algorithm, expected, remote,
                        repository.id(), repository.baseUrl().resolve(checksumPath).toString(),
                        true, matches));
                if (matches) {
                    anyMatch = true;
                    if (isStrongAlgorithm(algorithm)) strongMatch = true;
                } else {
                    mismatch = true;
                }
                continue;
            }

            if (config.downloadMissingArtifacts()) {
                if (downloadedArtifact == null) {
                    Path dir = workRoot != null ? workRoot : Files.createTempDirectory("dmr-artifact-");
                    downloadedArtifact = transport.download(relativePath, dir.resolve(repository.id()))
                            .orElse(null);
                }
                if (downloadedArtifact != null) {
                    try {
                        String actual = DigestUtils.hex(downloadedArtifact, algorithm);
                        boolean matches = trustedValues.contains(actual);
                        checks.add(new ChecksumCheck(algorithm, expected, actual,
                                repository.id(), repository.baseUrl().resolve(relativePath).toString(),
                                true, matches));
                        if (matches) {
                            anyMatch = true;
                            if (isStrongAlgorithm(algorithm)) strongMatch = true;
                        } else {
                            mismatch = true;
                        }
                    } catch (NoSuchAlgorithmException e) {
                        checks.add(ChecksumCheck.error(algorithm, expected,
                                repository.id(), checksumPath));
                        errors.add("Unsupported digest algorithm " + algorithm);
                    }
                } else {
                    checks.add(ChecksumCheck.notFound(algorithm, expected,
                            repository.id(), repository.baseUrl().resolve(checksumPath).toString()));
                }
            } else {
                checks.add(ChecksumCheck.notFound(algorithm, expected,
                        repository.id(), repository.baseUrl().resolve(checksumPath).toString()));
            }
        }

        boolean match = !mismatch && (strongMatch || (anyMatch && !hasStrongHash(record)));
        return new Attempt(match, mismatch, checks, errors);
    }

    private SignatureCheck maybeVerifySignature(
            MetadataRecord record,
            String relativePath,
            RepositoryConfig repository,
            RepositoryTransport transport,
            Set<String> trusted,
            ArtifactPolicy policy) {

        boolean configured = config.signatureMode() == ReviewConfig.SignatureMode.CONFIGURED
                && (!record.signers().isEmpty()
                    || !trusted.isEmpty()
                    || (policy != null && !policy.trustedFingerprints().isEmpty())
                    || (config.gpgKeyring() != null && !config.gpgKeyring().isBlank()));
        if (config.signatureMode() == ReviewConfig.SignatureMode.NONE
                || (config.signatureMode() == ReviewConfig.SignatureMode.CONFIGURED && !configured)) {
            return notRequested();
        }
        try {
            Path signatureWork = workRoot != null
                    ? Files.createDirectories(workRoot.resolve("signatures-work"))
                    : Files.createTempDirectory("dmr-pgp-");
            return signatureVerifier.verify(record, relativePath, transport,
                    repository.id(), signatureWork, trusted, config);
        } catch (Exception e) {
            return new SignatureCheck(SignatureCheck.Status.ERROR,
                    record.signers().isEmpty() ? null : record.signers().get(0).keyId(),
                    null, null, repository.id(), relativePath, e.getMessage());
        }
    }

    private static boolean hasStrongHash(MetadataRecord record) {
        return record.allHashes().anyMatch(HashValue::strong);
    }

    private static boolean isStrongAlgorithm(String algorithm) {
        return "sha256".equals(algorithm) || "sha384".equals(algorithm)
                || "sha512".equals(algorithm) || algorithm.startsWith("sha3-");
    }

    private static SignatureCheck notRequested() {
        return new SignatureCheck(SignatureCheck.Status.NOT_REQUESTED, null, null,
                null, null, null, "Signature verification not requested");
    }

    static String firstHexToken(String checksumFile) {
        if (checksumFile == null) {
            return "";
        }
        String trimmed = checksumFile.strip();
        int whitespace = -1;
        for (int i = 0; i < trimmed.length(); i++) {
            if (Character.isWhitespace(trimmed.charAt(i))) {
                whitespace = i;
                break;
            }
        }
        return (whitespace < 0 ? trimmed : trimmed.substring(0, whitespace)).toLowerCase();
    }

    private record Attempt(
            boolean match,
            boolean mismatch,
            List<ChecksumCheck> checks,
            List<String> errors) {
    }
}
