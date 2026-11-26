package com.example.depreview.config;

import com.example.depreview.model.Severity;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public record ReviewConfig(
        List<RepositoryConfig> repositories,
        Set<String> internalGroupPrefixes,
        Set<String> allowedSourceHosts,
        Set<String> trustedFingerprints,
        Map<String, ArtifactPolicy> policies,
        boolean online,
        SignatureMode signatureMode,
        Gate failOn,
        int timeoutSeconds,
        int parallelism,
        boolean downloadMissingArtifacts,
        String gpgExecutable,
        String gpgKeyring,
        int maxEvidenceLines) {

    public enum SignatureMode {
        NONE,
        CONFIGURED,
        ALL
    }

    public ReviewConfig {
        repositories = repositories == null ? List.of() : List.copyOf(repositories);
        internalGroupPrefixes = internalGroupPrefixes == null ? Set.of() : Set.copyOf(internalGroupPrefixes);
        allowedSourceHosts = allowedSourceHosts == null ? Set.of() : Set.copyOf(allowedSourceHosts);
        trustedFingerprints = trustedFingerprints == null ? Set.of() : Set.copyOf(trustedFingerprints);
        policies = policies == null ? Map.of() : Map.copyOf(policies);
        failOn = failOn == null ? Gate.HIGH : failOn;
        if (timeoutSeconds <= 0) timeoutSeconds = 20;
        if (parallelism <= 0) parallelism = Math.min(8, Runtime.getRuntime().availableProcessors());
        if (maxEvidenceLines <= 0) maxEvidenceLines = 20;
        gpgExecutable = gpgExecutable == null || gpgExecutable.isBlank() ? "gpg" : gpgExecutable;
        gpgKeyring = gpgKeyring == null ? "" : gpgKeyring;
    }

    public static ReviewConfig defaults() {
        return new ReviewConfig(
                List.of(new RepositoryConfig("maven-central",
                        URI.create("https://repo1.maven.org/maven2/"), false, false, null, null)),
                Set.of(),
                Set.of("repo1.maven.org"),
                Set.of(),
                Map.of(),
                true,
                SignatureMode.CONFIGURED,
                Gate.HIGH,
                20,
                4,
                true,
                "gpg",
                "",
                20);
    }

    public boolean isInternalCoordinate(String groupId) {
        return internalGroupPrefixes.stream().anyMatch(prefix ->
                groupId.equals(prefix) || groupId.startsWith(prefix + "."));
    }

    public Optional<ArtifactPolicy> policyFor(String groupId, String artifactId) {
        return policies.values().stream()
                .filter(p -> p.matches(groupId, artifactId))
                .findFirst();
    }

    public boolean isAllowedSourceHost(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String h = host.toLowerCase();
        return allowedSourceHosts.stream().anyMatch(allowed ->
                h.equals(allowed.toLowerCase()) || h.endsWith("." + allowed.toLowerCase()));
    }

    public ReviewConfig withOnline(boolean newOnline) {
        return new ReviewConfig(repositories, internalGroupPrefixes, allowedSourceHosts,
                trustedFingerprints, policies, newOnline, signatureMode, failOn, timeoutSeconds,
                parallelism, downloadMissingArtifacts, gpgExecutable, gpgKeyring, maxEvidenceLines);
    }

    public ReviewConfig withFailOn(Gate gate) {
        return new ReviewConfig(repositories, internalGroupPrefixes, allowedSourceHosts,
                trustedFingerprints, policies, online, signatureMode, gate, timeoutSeconds,
                parallelism, downloadMissingArtifacts, gpgExecutable, gpgKeyring, maxEvidenceLines);
    }

    public ReviewConfig withAllowedHosts(java.util.Set<String> hosts) {
        return new ReviewConfig(repositories, internalGroupPrefixes, hosts,
                trustedFingerprints, policies, online, signatureMode, failOn, timeoutSeconds,
                parallelism, downloadMissingArtifacts, gpgExecutable, gpgKeyring, maxEvidenceLines);
    }
}
