package io.depaudit.verify;

import io.depaudit.diff.MetadataDiffer;
import io.depaudit.model.ArtifactRef;
import io.depaudit.model.HashAlgorithm;
import io.depaudit.model.VerificationMetadata;
import io.depaudit.parse.VerificationMetadataParser;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UpgradeVerifierTest {

    private static final RepositoryConfig CENTRAL = new RepositoryConfig(
            "maven-central", "https://repo1.maven.org/maven2", TrustTier.CANONICAL, false);
    private static final RepositoryConfig INTERNAL = new RepositoryConfig(
            "internal", "https://nexus.corp/repo", TrustTier.INTERNAL, false);

    private static final String GOOD = "1".repeat(64);

    /** A metadata file with exactly one component at the given version, carrying {@code digest}. */
    private static VerificationMetadata md(String group, String name, String version,
                                           String fileName, String digest)
            throws Exception {
        String xml = """
                <?xml version="1.0"?>
                <verification-metadata>
                  <configuration><verify-metadata>true</verify-metadata></configuration>
                  <components>
                    <component group="%s" name="%s" version="%s">
                      <artifact name="%s">
                        <sha256 value="%s"/>
                      </artifact>
                    </component>
                  </components>
                </verification-metadata>
                """.formatted(group, name, version, fileName, digest);
        return new VerificationMetadataParser().parse(
                new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), "t.xml");
    }

    private static MetadataDiffer.Upgrade upgrade(String group, String name,
                                                  String from, String to) {
        return new MetadataDiffer.Upgrade(
                new ArtifactRef(group, name, from), new ArtifactRef(group, name, to), 5, 9);
    }

    private static VerificationPolicy policy(FakeRepositoryClient c, RepositoryConfig... repos) {
        return new VerificationPolicy(List.of(repos), c, false);
    }

    @Test
    void genuineBumpWhoseNewDigestMatchesCanonicalIsConfirmed() throws Exception {
        String gav = "com.example:widget:2.0";
        VerificationMetadata newMd = md("com.example", "widget", "2.0", "widget-2.0.jar", GOOD);
        FakeRepositoryClient c = new FakeRepositoryClient()
                .put("maven-central", gav, "widget-2.0.jar", HashAlgorithm.SHA256, GOOD);

        List<UpgradeVerifier.UpgradeVerification> r = new UpgradeVerifier(policy(c, CENTRAL))
                .verify(upgrade("com.example", "widget", "1.0", "2.0"), newMd);

        assertEquals(1, r.size());
        assertEquals(Verdict.CONFIRMED_CANONICAL, r.get(0).verdict());
        assertEquals(TrustTier.CANONICAL, r.get(0).tier());
    }

    @Test
    void bumpToAVersionCanonicalDoesNotHaveIsContradictory() throws Exception {
        // The attack the problem describes: someone edits the metadata to point at an
        // attacker-published artifact and dresses it up as a version upgrade. If the canonical
        // repository has never heard of the new version, that "upgrade" is fabricated.
        VerificationMetadata newMd = md("com.example", "widget", "99.0", "widget-99.0.jar", GOOD);
        FakeRepositoryClient c = new FakeRepositoryClient(); // canonical returns nothing

        List<UpgradeVerifier.UpgradeVerification> r = new UpgradeVerifier(policy(c, CENTRAL))
                .verify(upgrade("com.example", "widget", "1.0", "99.0"), newMd);

        assertEquals(Verdict.CONTRADICTED, r.get(0).verdict(),
                "a version the canonical repository never published is not a normal bump");
    }

    @Test
    void bumpWhoseNewDigestDisagreesWithCanonicalIsContradictory() throws Exception {
        String gav = "com.example:widget:2.0";
        VerificationMetadata newMd = md("com.example", "widget", "2.0", "widget-2.0.jar", GOOD);
        FakeRepositoryClient c = new FakeRepositoryClient()
                .put("maven-central", gav, "widget-2.0.jar", HashAlgorithm.SHA256, "9".repeat(64));

        List<UpgradeVerifier.UpgradeVerification> r = new UpgradeVerifier(policy(c, CENTRAL))
                .verify(upgrade("com.example", "widget", "1.0", "2.0"), newMd);

        assertEquals(Verdict.CONTRADICTED, r.get(0).verdict());
    }

    @Test
    void bumpOnlyInInternalRepositoryIsReportedAsInternalOnly() throws Exception {
        String gav = "com.corp:internal-lib:3.1";
        VerificationMetadata newMd = md("com.corp", "internal-lib", "3.1", "internal-lib-3.1.jar", GOOD);
        FakeRepositoryClient c = new FakeRepositoryClient()
                .put("internal", gav, "internal-lib-3.1.jar", HashAlgorithm.SHA256, GOOD);

        List<UpgradeVerifier.UpgradeVerification> r = new UpgradeVerifier(policy(c, CENTRAL, INTERNAL))
                .verify(upgrade("com.corp", "internal-lib", "3.0", "3.1"), newMd);

        assertEquals(Verdict.INTERNAL_ONLY, r.get(0).verdict(),
                "an artifact that only exists internally cannot be confirmed upstream");
        assertFalse(r.get(0).verdict() == Verdict.CONTRADICTED,
                "and must not be treated as an attack");
    }

    @Test
    void internalOnlyUpgradeDoesNotBecomeContradictionJustBecauseCanonicalLacksIt() throws Exception {
        // When the organisation has told us it uses an internal repository, absence from the
        // canonical repository is expected for internal-only artifacts. Only a canonical
        // disagreement over a version it *does* have is a contradiction.
        String gav = "com.corp:internal-lib:3.1";
        VerificationMetadata newMd = md("com.corp", "internal-lib", "3.1", "internal-lib-3.1.jar", GOOD);
        FakeRepositoryClient c = new FakeRepositoryClient()
                .put("internal", gav, "internal-lib-3.1.jar", HashAlgorithm.SHA256, GOOD);

        List<UpgradeVerifier.UpgradeVerification> r = new UpgradeVerifier(policy(c, CENTRAL, INTERNAL))
                .verify(upgrade("com.corp", "internal-lib", "3.0", "3.1"), newMd);
        assertTrue(r.get(0).evidence().stream().anyMatch(e -> e.contains("no configured repository")
                        || e.contains("internal") || e.contains("tier")),
                r.get(0).evidence().toString());
    }

    @Test
    void offlineUpgradeIsInconclusiveAndMakesNoCalls() throws Exception {
        VerificationMetadata newMd = md("com.example", "widget", "2.0", "widget-2.0.jar", GOOD);
        FakeRepositoryClient c = new FakeRepositoryClient();
        VerificationPolicy p = new VerificationPolicy(List.of(CENTRAL), c, true);

        List<UpgradeVerifier.UpgradeVerification> r = new UpgradeVerifier(p)
                .verify(upgrade("com.example", "widget", "1.0", "2.0"), newMd);

        assertEquals(Verdict.INCONCLUSIVE, r.get(0).verdict());
        assertTrue(c.calls().isEmpty(), c.calls().toString());
    }

    @Test
    void upgradeTargetMissingFromNewMetadataIsNotApplicable() throws Exception {
        VerificationMetadata newMd = md("com.example", "other", "1.0", "other-1.0.jar", GOOD);
        FakeRepositoryClient c = new FakeRepositoryClient();
        List<UpgradeVerifier.UpgradeVerification> r = new UpgradeVerifier(policy(c, CENTRAL))
                .verify(upgrade("com.example", "widget", "1.0", "2.0"), newMd);
        assertEquals(Verdict.NOT_APPLICABLE, r.get(0).verdict());
    }

    @Test
    void everyArtifactFileOfTheNewVersionIsVerified() throws Exception {
        String xml = """
                <?xml version="1.0"?>
                <verification-metadata>
                  <configuration><verify-metadata>true</verify-metadata></configuration>
                  <components>
                    <component group="g" name="n" version="2.0">
                      <artifact name="n-2.0.jar"><sha256 value="%s"/></artifact>
                      <artifact name="n-2.0.pom"><sha256 value="%s"/></artifact>
                    </component>
                  </components>
                </verification-metadata>
                """.formatted(GOOD, "2".repeat(64));
        VerificationMetadata newMd = new VerificationMetadataParser().parse(
                new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), "t.xml");

        FakeRepositoryClient c = new FakeRepositoryClient()
                .put("maven-central", "g:n:2.0", "n-2.0.jar", HashAlgorithm.SHA256, GOOD)
                .put("maven-central", "g:n:2.0", "n-2.0.pom", HashAlgorithm.SHA256, "2".repeat(64));

        List<UpgradeVerifier.UpgradeVerification> r = new UpgradeVerifier(policy(c, CENTRAL))
                .verify(upgrade("g", "n", "1.0", "2.0"), newMd);

        assertEquals(2, r.size(), "jar and pom are both verified");
        assertTrue(r.stream().allMatch(u -> u.verdict() == Verdict.CONFIRMED_CANONICAL));
    }

    @Test
    void oneBadArtifactFileMakesTheUpgradeContradictory() throws Exception {
        String xml = """
                <?xml version="1.0"?>
                <verification-metadata>
                  <configuration><verify-metadata>true</verify-metadata></configuration>
                  <components>
                    <component group="g" name="n" version="2.0">
                      <artifact name="n-2.0.jar"><sha256 value="%s"/></artifact>
                      <artifact name="n-2.0.pom"><sha256 value="%s"/></artifact>
                    </component>
                  </components>
                </verification-metadata>
                """.formatted(GOOD, "2".repeat(64));
        VerificationMetadata newMd = new VerificationMetadataParser().parse(
                new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), "t.xml");

        FakeRepositoryClient c = new FakeRepositoryClient()
                .put("maven-central", "g:n:2.0", "n-2.0.jar", HashAlgorithm.SHA256, GOOD)
                .put("maven-central", "g:n:2.0", "n-2.0.pom", HashAlgorithm.SHA256, "9".repeat(64));

        List<UpgradeVerifier.UpgradeVerification> r = new UpgradeVerifier(policy(c, CENTRAL))
                .verify(upgrade("g", "n", "1.0", "2.0"), newMd);

        assertTrue(r.stream().anyMatch(u -> u.verdict() == Verdict.CONTRADICTED),
                "a pom with the wrong digest is enough to reject the bump: " + r);
    }

    @Test
    void networkFailureOnUpgradeIsInconclusive() throws Exception {
        VerificationMetadata newMd = md("g", "n", "2.0", "n-2.0.jar", GOOD);
        FakeRepositoryClient c = new FakeRepositoryClient()
                .fail("maven-central", new java.io.IOException("timeout"));
        List<UpgradeVerifier.UpgradeVerification> r = new UpgradeVerifier(policy(c, CENTRAL))
                .verify(upgrade("g", "n", "1.0", "2.0"), newMd);
        assertEquals(Verdict.INCONCLUSIVE, r.get(0).verdict());
    }
}
