package com.example.depreview.analyze;

import com.example.depreview.config.ArtifactPolicy;
import com.example.depreview.config.ReviewConfig;
import com.example.depreview.diff.BuildCorrelator;
import com.example.depreview.model.ArtifactMutation;
import com.example.depreview.model.BuildEvidence;
import com.example.depreview.model.Coordinates;
import com.example.depreview.model.Finding;
import com.example.depreview.model.HashValue;
import com.example.depreview.model.HashChange;
import com.example.depreview.model.MutationKind;
import com.example.depreview.model.ReviewReport;
import com.example.depreview.model.Severity;
import com.example.depreview.model.SignerChange;
import com.example.depreview.model.UrlChange;
import com.example.depreview.model.VerifiedChange;
import com.example.depreview.verify.SignatureCheck;
import com.example.depreview.verify.VerificationResult;
import com.example.depreview.verify.VerificationService;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public final class ReviewEngine {

    private final ReviewConfig config;
    private final VerificationService verificationService;
    private final BuildCorrelator buildCorrelator;

    public ReviewEngine(
            ReviewConfig config,
            VerificationService verificationService,
            BuildCorrelator buildCorrelator) {
        this.config = config;
        this.verificationService = verificationService;
        this.buildCorrelator = buildCorrelator;
    }

    public ReviewReport review(List<ArtifactMutation> mutations) {
        return review(mutations, List.of());
    }

    public ReviewReport review(List<ArtifactMutation> mutations, List<Finding> policyFindings) {
        Map<ArtifactMutation, VerificationResult> verification = verifyAll(mutations);
        List<Finding> findings = new ArrayList<>();
        List<VerifiedChange> verified = new ArrayList<>();
        List<String> notices = new ArrayList<>();

        for (ArtifactMutation mutation : mutations) {
            VerificationResult result = verification.get(mutation);
            BuildEvidence evidence = correlate(mutation);
            Outcome outcome = evaluate(mutation, result, evidence);
            outcome.finding.ifPresent(findings::add);
            outcome.verified.ifPresent(verified::add);
        }
        if (policyFindings != null) {
            findings.addAll(policyFindings);
        }

        long blocking = findings.stream().filter(f -> config.failOn().blocks(f.getSeverity())).count();
        String verdict;
        if (blocking > 0) {
            verdict = "FAIL";
        } else if (!findings.isEmpty()) {
            verdict = "PASS_WITH_REVIEW_ITEMS";
        } else {
            verdict = "PASS";
        }

        if (!config.online()) {
            notices.add("Offline/diff-only mode: official repository and signature checks were not performed.");
        }
        if (buildCorrelator == null) {
            notices.add("No build-file patch was provided; version declaration correlation was skipped.");
        }

        return new ReviewReport(
                verdict,
                config.failOn(),
                mutations.size(),
                verified.size(),
                verified,
                findings,
                notices);
    }

    private BuildEvidence correlate(ArtifactMutation mutation) {
        if (buildCorrelator == null) {
            return BuildEvidence.notProvided();
        }
        return buildCorrelator.correlate(mutation.oldCoordinates(), mutation.newCoordinates());
    }

    private Map<ArtifactMutation, VerificationResult> verifyAll(List<ArtifactMutation> mutations) {
        ExecutorService executor = Executors.newFixedThreadPool(
                Math.max(1, Math.min(config.parallelism(), Math.max(1, mutations.size()))));
        try {
            List<CompletableFuture<Map.Entry<ArtifactMutation, VerificationResult>>> futures =
                    mutations.stream()
                            .filter(m -> m.newRecord() != null)
                            .map(m -> CompletableFuture.supplyAsync(() -> {
                                try {
                                    return Map.entry(m, verificationService.verify(m.newRecord()));
                                } catch (Exception e) {
                                    VerificationResult error = new VerificationResult(
                                            VerificationResult.Status.ERROR, null, null, List.of(),
                                            new SignatureCheck(SignatureCheck.Status.ERROR, null,
                                                    null, null, null, null, e.getMessage()),
                                            e.getMessage());
                                    return Map.entry(m, error);
                                }
                            }, executor))
                            .toList();

            Map<ArtifactMutation, VerificationResult> results = new LinkedHashMap<>();
            for (CompletableFuture<Map.Entry<ArtifactMutation, VerificationResult>> future : futures) {
                Map.Entry<ArtifactMutation, VerificationResult> entry = future.join();
                results.put(entry.getKey(), entry.getValue());
            }
            return results;
        } finally {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(30, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    private Outcome evaluate(
            ArtifactMutation mutation,
            VerificationResult verification,
            BuildEvidence buildEvidence) {

        Coordinates coordinates = mutation.primaryCoordinates();
        Optional<ArtifactPolicy> policy = coordinates == null ? Optional.empty()
                : config.policyFor(coordinates.groupId(), coordinates.artifactId());
        Severity severity = Severity.INFO;
        List<String> changes = new ArrayList<>();
        List<String> evidenceLines = new ArrayList<>();
        List<String> recommendations = new ArrayList<>();
        boolean createFinding;

        for (HashChange change : mutation.hashChanges()) {
            changes.add(describeHashChange(change));
            if (change.oldLine() != null || change.newLine() != null) {
                evidenceLines.add("hash " + change.algorithm()
                        + " oldLine=" + change.oldLine() + " newLine=" + change.newLine());
            }
            if (change.valueChanged() && mutation.kind() == MutationKind.SAME_VERSION) {
                severity = max(severity, Severity.HIGH);
                recommendations.add("Reject a same-version checksum rotation unless the artifact was intentionally rebuilt and the new digest is independently confirmed.");
            } else if (change.removed() && mutation.newRecord() != null
                    && mutation.newRecord().hashes().isEmpty()) {
                severity = max(severity, Severity.HIGH);
                recommendations.add("Do not remove the last checksum verifier for an artifact.");
            } else if (change.removed()) {
                severity = max(severity, Severity.MEDIUM);
            } else if (change.added()) {
                severity = max(severity, Severity.LOW);
            }
        }

        for (UrlChange change : mutation.urlChanges()) {
            changes.add(describeUrlChange(change));
            evidenceLines.add("source oldLine=" + change.oldLine() + " newLine=" + change.newLine());
            if (change.newUrl() != null) {
                String host = hostOf(change.newUrl());
                boolean allowed = config.isAllowedSourceHost(host);
                if (!allowed) {
                    severity = max(severity, Severity.CRITICAL);
                    recommendations.add("Block the merge: the new source host '" + host
                            + "' is not in the approved repository allow-list. Confirm this is not a typosquatted or backdoored same-name artifact.");
                } else if (change.changed()) {
                    severity = max(severity, Severity.MEDIUM);
                    recommendations.add("Confirm the source move between approved repositories is intentional.");
                }
            } else {
                severity = max(severity, Severity.LOW);
            }
        }

        for (SignerChange change : mutation.signerChanges()) {
            changes.add("PGP pin: " + nullToNone(change.oldKeyId()) + " -> " + nullToNone(change.newKeyId()));
            if (change.newKeyId() != null) {
                severity = max(severity, Severity.HIGH);
                recommendations.add("Verify the new signing fingerprint against the project's out-of-band KEYS file or source repository, not only the keyserver UID.");
            } else {
                severity = max(severity, Severity.MEDIUM);
            }
        }

        if (containsWeakOnlyHash(mutation)) {
            severity = max(severity, Severity.MEDIUM);
            recommendations.add("Add a strong SHA-256/SHA-512 digest; MD5 and SHA-1 are collision-weak.");
        }

        if (verification != null) {
            severity = max(severity, applySignatureSeverity(verification, severity));
            if (verification.status() == VerificationResult.Status.CHECKSUM_MISMATCH) {
                severity = Severity.CRITICAL;
                recommendations.add("The metadata digest does not match the repository digest. Do not merge until the discrepancy is explained out-of-band.");
            }
        }

        boolean versionChange = mutation.kind() == MutationKind.VERSION_UPGRADE
                || mutation.kind() == MutationKind.VERSION_DOWNGRADE
                || mutation.kind() == MutationKind.NEW_VERSION_PARALLEL;
        boolean added = mutation.kind() == MutationKind.ADDED;
        boolean removed = mutation.kind() == MutationKind.REMOVED;

        if (removed && !changes.isEmpty()) {
            createFinding = true;
            severity = max(severity, Severity.LOW);
        } else if (removed) {
            return Outcome.empty();
        } else if (versionChange || added) {
            if (verification != null && verification.verified()) {
                if (verification.status() == VerificationResult.Status.INTERNAL_MATCH
                        && coordinates != null
                        && !config.isInternalCoordinate(coordinates.groupId())
                        && policy.map(p -> !p.allowRepositorySpecificArtifact()).orElse(true)) {
                    severity = max(severity, Severity.HIGH);
                    recommendations.add("This public-looking coordinate only matched a non-public repository. Add a narrow repository-variant policy with a reason if that rebuild is legitimate.");
                    createFinding = true;
                } else if (severity.atLeast(Severity.MEDIUM)) {
                    createFinding = true;
                } else {
                    createFinding = false;
                    VerifiedChange verifiedChange = new VerifiedChange(
                            coordinates == null ? "" : coordinates.gav(),
                            mutation.newRecord().artifactName(),
                            verification.repositoryId(),
                            verification.status().name(),
                            verification.signatureCheck() == null ? "NONE"
                                    : verification.signatureCheck().status().name());
                    applySignatureSeverity(verification, severity);
                    return new Outcome(Optional.empty(), Optional.of(verifiedChange));
                }
            } else {
                severity = max(severity, severityForUnverifiedVersion(mutation, verification, config));
                recommendations.add(recommendationForUnverified(verification, coordinates, config));
                createFinding = true;
            }
        } else {
            // SAME_VERSION or an in-place artifact change is always surfaced.
            createFinding = true;
        }

        Severity signatureSeverity = applySignatureSeverity(verification, severity);
        severity = max(severity, signatureSeverity);
        if (verification != null && verification.status() == VerificationResult.Status.CHECKSUM_MISMATCH) {
            severity = Severity.CRITICAL;
        }

        if (buildEvidence != null && buildEvidence.buildPatchProvided()
                && versionChange && !buildEvidence.newVersionDeclared()) {
            recommendations.add("No literal version edit was found in the supplied build patch. This may be a BOM/platform/constraint upgrade or a missing/wrong --build-patch; confirm the resolved version.");
        }

        if (policy.isPresent() && policy.get().allowSameVersionHashChange()
                && verification != null && verification.verified()
                && mutation.kind() == MutationKind.SAME_VERSION
                && severity != Severity.CRITICAL) {
            severity = Severity.LOW;
            recommendations.add("Allowed by explicit artifact policy: " + policy.get().reason());
        }

        if (!createFinding && !severity.atLeast(Severity.LOW)) {
            VerifiedChange verifiedChange = new VerifiedChange(
                    coordinates == null ? "" : coordinates.gav(),
                    mutation.primaryRecord() == null ? "" : mutation.primaryRecord().artifactName(),
                    verification == null ? null : verification.repositoryId(),
                    verification == null ? "NOT_VERIFIED" : verification.status().name(),
                    verification != null && verification.signatureCheck() != null
                            ? verification.signatureCheck().status().name() : "NONE");
            return new Outcome(Optional.empty(), Optional.of(verifiedChange));
        }

        String id = stableId(mutation, changes);
        String title = titleFor(severity, mutation.kind());
        Finding.Builder builder = Finding.builder(id, severity, title)
                .mutation(mutation)
                .buildEvidence(buildEvidence)
                .verification(verification)
                .recommendation(String.join(" ", recommendations));
        changes.forEach(builder::addChange);
        evidenceLines.forEach(builder::addEvidenceLine);
        if (verification != null) {
            builder.addEvidenceLine("verification=" + verification.status()
                    + " repository=" + nullToNone(verification.repositoryId())
                    + " message=" + verification.message());
            if (verification.signatureCheck() != null) {
                builder.addEvidenceLine("signature=" + verification.signatureCheck().status()
                        + " fingerprint=" + nullToNone(verification.signatureCheck().fingerprint()));
            }
        }
        buildEvidence.matchingLines().forEach(builder::addEvidenceLine);
        return new Outcome(Optional.of(builder.build()), Optional.empty());
    }

    private static Severity severityForUnverifiedVersion(
            ArtifactMutation mutation, VerificationResult result, ReviewConfig config) {
        if (result == null) {
            return Severity.HIGH;
        }
        return switch (result.status()) {
            case CHECKSUM_MISMATCH -> Severity.CRITICAL;
            case OFFLINE -> Severity.HIGH;
            case INTERNAL_UNAVAILABLE, ERROR -> Severity.HIGH;
            case NO_REPOSITORY_MATCH -> {
                Coordinates c = mutation.primaryCoordinates();
                yield c != null && config.isInternalCoordinate(c.groupId())
                        ? Severity.MEDIUM : Severity.HIGH;
            }
            default -> Severity.MEDIUM;
        };
    }

    private static String recommendationForUnverified(
            VerificationResult result, Coordinates coordinates, ReviewConfig config) {
        if (result == null) {
            return "No verification result was produced; inspect this record manually.";
        }
        if (result.status() == VerificationResult.Status.NO_REPOSITORY_MATCH
                && coordinates != null
                && config.isInternalCoordinate(coordinates.groupId())) {
            return "Internal-only coordinate: compare with the internal repository or approve a narrow internal policy.";
        }
        return switch (result.status()) {
            case CHECKSUM_MISMATCH -> "Reject: checksum mismatch against a configured repository.";
            case OFFLINE -> "Re-run online or manually compare the digest with the official repository/project KEYS.";
            case NO_REPOSITORY_MATCH ->
                    "The GAV/artifact was not found in configured repositories. Check the artifact filename, classifier, repository list, and possible dependency-confusion.";
            case INTERNAL_UNAVAILABLE, ERROR ->
                    "A configured repository could not be verified. Check credentials/network and re-run rather than bypassing the gate.";
            default -> result.message();
        };
    }

    private static Severity applySignatureSeverity(VerificationResult result, Severity current) {
        if (result == null || result.signatureCheck() == null) {
            return current;
        }
        SignatureCheck signature = result.signatureCheck();
        return switch (signature.status()) {
            case INVALID -> Severity.CRITICAL;
            case VALID_UNTRUSTED -> max(current, Severity.HIGH);
            case ERROR -> max(current, Severity.MEDIUM);
            case NOT_CONFIGURED -> max(current, Severity.LOW);
            case NOT_FOUND -> max(current, Severity.LOW);
            default -> current;
        };
    }

    private static boolean containsWeakOnlyHash(ArtifactMutation mutation) {
        if (mutation.newRecord() == null || mutation.newRecord().hashes().isEmpty()) {
            return false;
        }
        return mutation.newRecord().allHashes().noneMatch(HashValue::strong);
    }

    private static String describeHashChange(HashChange change) {
        return change.algorithm() + ": " + nullToNone(change.oldValue())
                + " -> " + nullToNone(change.newValue());
    }

    private static String describeUrlChange(UrlChange change) {
        return "source: " + nullToNone(change.oldUrl()) + " -> " + nullToNone(change.newUrl());
    }

    private static String hostOf(String url) {
        try {
            URI uri = URI.create(url);
            return uri.getHost() == null ? "" : uri.getHost().toLowerCase();
        } catch (Exception e) {
            return "";
        }
    }

    private static String nullToNone(String value) {
        return value == null || value.isBlank() ? "<none>" : value;
    }

    private static Severity max(Severity a, Severity b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    private static String titleFor(Severity severity, MutationKind kind) {
        if (severity == Severity.CRITICAL) {
            return "Critical dependency metadata change requires blocking review";
        }
        if (kind == MutationKind.SAME_VERSION) {
            return "Checksum/provenance changed for an unchanged version";
        }
        if (kind == MutationKind.VERSION_DOWNGRADE) {
            return "Dependency version downgrade and metadata change";
        }
        return "Dependency metadata change needs review";
    }

    private static String stableId(ArtifactMutation mutation, List<String> changes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String base = mutation.metadataFile() + "|"
                    + (mutation.primaryCoordinates() == null ? "" : mutation.primaryCoordinates().gav())
                    + "|" + mutation.stableArtifact() + "|" + mutation.kind() + "|"
                    + String.join(";", changes);
            byte[] hash = digest.digest(base.getBytes(StandardCharsets.UTF_8));
            return "DMR-" + HexFormat.of().formatHex(hash).substring(0, 16);
        } catch (Exception e) {
            return "DMR-" + Integer.toHexString((mutation.metadataFile() + changes).hashCode());
        }
    }

    private record Outcome(Optional<Finding> finding, Optional<VerifiedChange> verified) {
        static Outcome empty() {
            return new Outcome(Optional.empty(), Optional.empty());
        }
    }
}
