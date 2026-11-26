package com.example.depreview.config;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Explicit exception for a group or group:artifact. Policies should be narrow and carry a reason;
 * they are how an internal fork or repository-specific rebuild is distinguished from an attack.
 */
public record ArtifactPolicy(
        String key,
        boolean allowSameVersionHashChange,
        boolean allowRepositorySpecificArtifact,
        Set<String> allowedRepositoryIds,
        Set<String> approvedHashes,
        Set<String> trustedFingerprints,
        String reason) {

    public ArtifactPolicy {
        allowedRepositoryIds = allowedRepositoryIds == null ? Set.of() : Set.copyOf(allowedRepositoryIds);
        approvedHashes = approvedHashes == null ? Set.of() : normalizeHashes(approvedHashes);
        trustedFingerprints = trustedFingerprints == null ? Set.of() : normalizeUpper(trustedFingerprints);
    }

    private static Set<String> normalizeHashes(Set<String> input) {
        Set<String> out = new LinkedHashSet<>();
        input.forEach(h -> out.add(h.trim().toLowerCase()));
        return Set.copyOf(out);
    }

    private static Set<String> normalizeUpper(Set<String> input) {
        Set<String> out = new LinkedHashSet<>();
        input.forEach(h -> out.add(h.trim().toUpperCase()));
        return Set.copyOf(out);
    }

    public boolean matches(String groupId, String artifactId) {
        return key.equals(groupId) || key.equals(groupId + ":" + artifactId);
    }
}
