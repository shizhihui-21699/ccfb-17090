package com.example.depreview.verify;

import com.example.depreview.analyze.ReviewEngine;
import com.example.depreview.config.ArtifactPolicy;
import com.example.depreview.config.Gate;
import com.example.depreview.config.RepositoryConfig;
import com.example.depreview.config.ReviewConfig;
import com.example.depreview.model.ArtifactMutation;
import com.example.depreview.model.Coordinates;
import com.example.depreview.model.HashChange;
import com.example.depreview.model.HashValue;
import com.example.depreview.model.MetadataRecord;
import com.example.depreview.model.MutationKind;
import com.example.depreview.model.ReviewReport;
import com.example.depreview.model.Severity;
import com.example.depreview.model.SourceRef;
import com.example.depreview.model.UrlChange;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReviewEngineTest {

    private static final String HASH_A = "a".repeat(64);
    private static final String HASH_B = "b".repeat(64);
    private static final String HASH_C = "c".repeat(64);

    @Test
    void unchangedVersionHashAndUapprovedSourceIsCriticalMismatch() {
        Coordinates coordinates = new Coordinates("com.acme", "secure-lib", "1.0");
        MetadataRecord oldRecord = record(coordinates, "secure-lib-1.0.jar", HASH_A,
                new SourceRef("https://approved.example/secure-lib-1.0.jar", "source", 10));
        MetadataRecord newRecord = record(coordinates, "secure-lib-1.0.jar", HASH_B,
                new SourceRef("https://evil.example.test/secure-lib-1.0.jar", "source", 12));
        ArtifactMutation mutation = new ArtifactMutation(
                "gradle/verification-metadata.xml", MutationKind.SAME_VERSION,
                oldRecord, newRecord, coordinates, coordinates, newRecord.stableKey(),
                List.of(new HashChange("sha256", HASH_A, HASH_B, 11, 13)),
                List.of(new UrlChange("https://approved.example/secure-lib-1.0.jar",
                        "https://evil.example.test/secure-lib-1.0.jar", 10, 12)),
                List.of());

        FakeTransport central = new FakeTransport("central", Map.of(
                "com/acme/secure-lib/1.0/secure-lib-1.0.jar.sha256", HASH_C));
        ReviewReport report = review(config(List.of(central.repository()), Set.of("approved.example"),
                Set.of(), Gate.HIGH), Map.of("central", central), List.of(mutation));

        assertTrue(report.failed());
        assertEquals(1, report.severityCounts().get(Severity.CRITICAL));
        assertTrue(report.findings().get(0).getChanges().toString().contains("evil.example.test"));
    }

    @Test
    void matchedVersionUpgradeIsVerifiedWithoutBlockingFinding() {
        Coordinates oldCoordinates = new Coordinates("com.acme", "web-lib", "1.0");
        Coordinates newCoordinates = new Coordinates("com.acme", "web-lib", "2.0");
        MetadataRecord oldRecord = record(oldCoordinates, "web-lib-1.0.jar", HASH_A);
        MetadataRecord newRecord = record(newCoordinates, "web-lib-2.0.jar", HASH_B);
        ArtifactMutation mutation = new ArtifactMutation(
                "verification-metadata.xml", MutationKind.VERSION_UPGRADE,
                oldRecord, newRecord, oldCoordinates, newCoordinates, newRecord.stableKey(),
                List.of(new HashChange("sha256", HASH_A, HASH_B, 1, 2)),
                List.of(), List.of());

        String checksumPath = "com/acme/web-lib/2.0/web-lib-2.0.jar.sha256";
        FakeTransport central = new FakeTransport("central", Map.of(checksumPath, HASH_B));
        ReviewReport report = review(config(List.of(central.repository()), Set.of(), Set.of(), Gate.HIGH),
                Map.of("central", central), List.of(mutation));

        assertFalse(report.failed());
        assertEquals(1, report.verifiedUpgradeCount());
        assertTrue(report.findings().isEmpty());
    }

    @Test
    void alsoTrustAlternativeDigestMatchesRepositorySpecificBuild() {
        Coordinates oldCoordinates = new Coordinates("com.acme", "variant", "1.0");
        Coordinates newCoordinates = new Coordinates("com.acme", "variant", "2.0");
        HashValue hash = new HashValue("sha256", HASH_A, "Gradle", null, List.of(HASH_B));
        MetadataRecord oldRecord = record(oldCoordinates, "variant-1.0.jar", HASH_A);
        MetadataRecord newRecord = new MetadataRecord(
                newCoordinates, "variant-2.0.jar",
                Map.of("sha256", List.of(hash)), List.of(), List.of(), null);
        ArtifactMutation mutation = new ArtifactMutation(
                "verification-metadata.xml", MutationKind.VERSION_UPGRADE,
                oldRecord, newRecord, oldCoordinates, newCoordinates, newRecord.stableKey(),
                List.of(), List.of(), List.of());

        FakeTransport central = new FakeTransport("central", Map.of(
                "com/acme/variant/2.0/variant-2.0.jar.sha256", HASH_B));
        ReviewReport report = review(
                config(List.of(central.repository()), Set.of(), Set.of(), Gate.HIGH),
                Map.of("central", central), List.of(mutation));

        assertFalse(report.failed());
        assertEquals(1, report.verifiedUpgradeCount());
    }

    @Test
    void internalOnlyMissingExternalArtifactIsMediumNotFalseCritical() {
        Coordinates oldCoordinates = new Coordinates("com.internal", "client", "1.0");
        Coordinates newCoordinates = new Coordinates("com.internal", "client", "2.0");
        MetadataRecord oldRecord = record(oldCoordinates, "client-1.0.jar", HASH_A);
        MetadataRecord newRecord = record(newCoordinates, "client-2.0.jar", HASH_B);
        ArtifactMutation mutation = new ArtifactMutation(
                "verification-metadata.xml", MutationKind.VERSION_UPGRADE,
                oldRecord, newRecord, oldCoordinates, newCoordinates, newRecord.stableKey(),
                List.of(new HashChange("sha256", HASH_A, HASH_B, null, null)),
                List.of(), List.of());

        FakeTransport internal = new FakeTransport("internal", Map.of());
        ReviewConfig config = config(List.of(internal.repository()), Set.of("com.internal"),
                Set.of(), Gate.HIGH);
        ReviewReport report = review(config, Map.of("internal", internal), List.of(mutation));

        assertFalse(report.failed());
        assertEquals(1, report.severityCounts().get(Severity.MEDIUM));
    }

    @Test
    void repositorySpecificArtifactRequiresPolicyUnlessExplicitlyAllowed() {
        Coordinates oldCoordinates = new Coordinates("com.acme", "fork", "1.0");
        Coordinates newCoordinates = new Coordinates("com.acme", "fork", "2.0");
        MetadataRecord oldRecord = record(oldCoordinates, "fork-1.0.jar", HASH_A);
        MetadataRecord newRecord = record(newCoordinates, "fork-2.0.jar", HASH_B);
        ArtifactMutation mutation = new ArtifactMutation(
                "verification-metadata.xml", MutationKind.VERSION_UPGRADE,
                oldRecord, newRecord, oldCoordinates, newCoordinates, newRecord.stableKey(),
                List.of(new HashChange("sha256", HASH_A, HASH_B, null, null)),
                List.of(), List.of());
        String path = "com/acme/fork/2.0/fork-2.0.jar.sha256";
        FakeTransport central = new FakeTransport("central", Map.of());
        FakeTransport internal = new FakeTransport("internal", Map.of(path, HASH_B));

        ReviewReport withoutPolicy = review(
                config(List.of(central.repository(), internal.repository()), Set.of(), Set.of(), Gate.HIGH),
                Map.of("central", central, "internal", internal), List.of(mutation));
        assertTrue(withoutPolicy.failed());
        assertEquals(1, withoutPolicy.severityCounts().get(Severity.HIGH));

        ArtifactPolicy policy = new ArtifactPolicy("com.acme:fork", false, true,
                Set.of("internal"), Set.of(), Set.of(), "Reproduced internally with classifier metadata");
        ReviewConfig allowed = config(List.of(internal.repository()), Set.of(),
                Map.of("com.acme:fork", policy), Gate.HIGH);
        ReviewReport withPolicy = review(allowed, Map.of("internal", internal), List.of(mutation));
        assertFalse(withPolicy.failed());
        assertEquals(1, withPolicy.verifiedUpgradeCount());
    }

    private static ReviewReport review(
            ReviewConfig config,
            Map<String, RepositoryTransport> transports,
            List<ArtifactMutation> mutations) {
        VerificationService verificationService = new VerificationService(
                config, Set.of(), transports, null, new GpgSignatureVerifier());
        return new ReviewEngine(config, verificationService, null).review(mutations);
    }

    private static ReviewConfig config(
            List<RepositoryConfig> repositories,
            Set<String> internalPrefixes,
            Set<String> allowedHosts,
            Gate gate) {
        return config(repositories, internalPrefixes, Map.of(), gate).withAllowedHosts(allowedHosts);
    }

    private static ReviewConfig config(
            List<RepositoryConfig> repositories,
            Set<String> internalPrefixes,
            Map<String, ArtifactPolicy> policies,
            Gate gate) {
        return new ReviewConfig(
                repositories,
                internalPrefixes,
                Set.of("repo.example"),
                Set.of(),
                policies,
                true,
                ReviewConfig.SignatureMode.NONE,
                gate,
                5,
                1,
                false,
                "gpg",
                "",
                10);
    }

    private static MetadataRecord record(
            Coordinates coordinates, String artifactName, String hash, SourceRef... sources) {
        return new MetadataRecord(
                coordinates,
                artifactName,
                Map.of("sha256", List.of(new HashValue("sha256", hash, "test", null))),
                List.of(sources),
                List.of(),
                null);
    }

    private static final class FakeTransport implements RepositoryTransport {
        private final String id;
        private final RepositoryConfig repository;
        private final Map<String, String> texts;

        private FakeTransport(String id, Map<String, String> texts) {
            this.id = id;
            boolean publicRepo = "central".equals(id);
            this.repository = new RepositoryConfig(id,
                    URI.create("https://repo.example/" + id + "/"), publicRepo, !publicRepo, null, null);
            this.texts = texts;
        }

        private RepositoryConfig repository() {
            return repository;
        }

        @Override
        public String id() {
            return id;
        }

        @Override
        public Optional<String> getString(String relativePath) {
            return Optional.ofNullable(texts.get(relativePath));
        }

        @Override
        public Optional<Path> download(String relativePath, Path targetDirectory) {
            return Optional.empty();
        }
    }
}
